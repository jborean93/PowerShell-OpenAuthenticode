using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;

namespace OpenAuthenticode.Commands;

public abstract class AsyncPSCmdlet : PSCmdlet, IDisposable
{
    private bool _disposed = false;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

// PowerShell 7.6 introduces a builtin PipelineStopToken, for older versions we
// implement our own cancellation stop trigger and its cleanup. Once 7.6 is the
// baseline we can remove the else block.
#if NET10_0_OR_GREATER
    protected virtual void Dispose(bool disposing)
    {
    }
#else
    private CancellationTokenSource _cancelSource = new();

    public CancellationToken PipelineStopToken => _cancelSource.Token;

    protected override void StopProcessing()
    {
        _cancelSource.Cancel();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _cancelSource.Dispose();
        }

        _disposed = true;
    }
#endif

    protected override void BeginProcessing()
        => RunBlockInAsync(BeginProcessingAsync);

    protected virtual Task BeginProcessingAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
        => Task.CompletedTask;

    protected override void ProcessRecord()
        => RunBlockInAsync(ProcessRecordAsync);

    protected virtual Task ProcessRecordAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
        => Task.CompletedTask;

    protected override void EndProcessing()
        => RunBlockInAsync(EndProcessingAsync);

    protected virtual Task EndProcessingAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
        => Task.CompletedTask;

    private void RunBlockInAsync(Func<AsyncPipeline, CancellationToken, Task> task)
    {
        // Create the output pipeline and hook up the stop token to complete it
        // if stopping. This will ensure the AsyncCmdlet knows when to emit the
        // PipelineStoppedException as needed.
        using BlockingCollection<(AsyncPipelineType, object?)> outPipe = new();
        using var _ = PipelineStopToken.Register(() => outPipe.CompleteAdding());

        AsyncPipeline cmdlet = new(MyInvocation, outPipe);

        // Kick off the async task in the background.
        Task blockTask = Task.Run(async () =>
        {
            try
            {
                await task(cmdlet, PipelineStopToken);
            }
            finally
            {
                // Ensure the output pipeline is marked as complete when the task
                // finishes. This ensures the consuming loop below can exit.
                outPipe.CompleteAdding();
            }
        });

        // Consume the data intended for the PowerShell pipeline as they arrive.
        foreach ((AsyncPipelineType pipelineType, object? data) in outPipe.GetConsumingEnumerable(PipelineStopToken))
        {
            switch (pipelineType)
            {
                case AsyncPipelineType.Output:
                    AsyncOutputRecord output = (AsyncOutputRecord)data!;
                    WriteObject(output.Data, output.EnumerateCollection);
                    output.CompletionSource?.TrySetResult();
                    break;

                case AsyncPipelineType.Error:
                    AsyncErrorRecord error = (AsyncErrorRecord)data!;
                    WriteError(error.Error);
                    error.CompletionSource.TrySetResult();
                    break;

                case AsyncPipelineType.Warning:
                    WriteWarning((string)data!);
                    break;

                case AsyncPipelineType.Verbose:
                    WriteVerbose((string)data!);
                    break;

                case AsyncPipelineType.Debug:
                    WriteDebug((string)data!);
                    break;

                case AsyncPipelineType.Information:
                    WriteInformation((InformationRecord)data!);
                    break;

                case AsyncPipelineType.Progress:
                    WriteProgress((ProgressRecord)data!);
                    break;

                case AsyncPipelineType.ShouldProcess:
                    ShouldProcessRecord shouldProcess = (ShouldProcessRecord)data!;
                    try
                    {
                        bool res = ShouldProcess(shouldProcess.Target, shouldProcess.Action);
                        shouldProcess.CompletionSource.TrySetResult(res);
                    }
                    catch (Exception ex)
                    {
                        shouldProcess.CompletionSource.TrySetException(ex);
                    }
                    break;

                case AsyncPipelineType.ScriptBlock:
                    ScriptRecord scriptRecord = (ScriptRecord)data!;
                    InvokeScriptReturnAsIs(
                        scriptRecord.ScriptBlock,
                        scriptRecord.ArgumentList,
                        scriptRecord.ReturnType,
                        scriptRecord.CompletionSource,
                        scriptRecord.CancellationToken);

                    break;
            }
        }

        blockTask.GetAwaiter().GetResult();
    }

    private static void InvokeScriptReturnAsIs(
        string script,
        object?[] argumentList,
        Type returnType,
        TaskCompletionSource<object?> tcs,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using PowerShell ps = PowerShell.Create(RunspaceMode.CurrentRunspace);

            // This is the cancellation token from the async call and isn't
            // always the one hooked up to the pipeline stop signal. If set
            // we want it to call BeginStop and not Stop so it doesn't block.
            using var _ = cancellationToken.Register(() => ps.BeginStop((r) => ps.EndStop(r), null));

            ps.AddScript(script);
            foreach (object? arg in argumentList)
            {
                ps.AddArgument(arg);
            }

            // Either the caller's cancellationToken will call BeginStop or the
            // cmdlet pipeline will trigger the runspace to stop so we can just
            // call Invoke() here.
            PSObject? result = ps.Invoke().FirstOrDefault();
            object? convertedResult = LanguagePrimitives.ConvertTo(result, returnType);
            tcs.TrySetResult(convertedResult);
        }
        catch (Exception ex)
        {
            tcs.TrySetException(ex);
        }
    }
}

internal enum AsyncPipelineType
{
    Output,
    Error,
    Warning,
    Verbose,
    Debug,
    Information,
    Progress,
    ShouldProcess,
    ScriptBlock,
}

internal record AsyncOutputRecord(object? Data, bool EnumerateCollection, TaskCompletionSource CompletionSource);
internal record AsyncErrorRecord(ErrorRecord Error, TaskCompletionSource CompletionSource);
internal record ShouldProcessRecord(string Target, string Action, TaskCompletionSource<bool> CompletionSource);
internal record ScriptRecord(string ScriptBlock, object?[] ArgumentList, Type ReturnType, TaskCompletionSource<object?> CompletionSource, CancellationToken CancellationToken);

public sealed class AsyncPipeline
{
    private readonly InvocationInfo _myInvocation;
    private readonly BlockingCollection<(AsyncPipelineType, object?)> _pipeline;

    internal AsyncPipeline(
        InvocationInfo myInvocation,
        BlockingCollection<(AsyncPipelineType, object?)> pipeline)
    {
        _myInvocation = myInvocation;
        _pipeline = pipeline;
    }

    public async ValueTask<bool> ShouldProcessAsync(
        string target,
        string action,
        CancellationToken cancellationToken = default)
    {
        TaskCompletionSource<bool> tcs = new();
        using var _ = cancellationToken.Register(() => tcs.TrySetCanceled());

        WritePipeline(AsyncPipelineType.ShouldProcess, new ShouldProcessRecord(target, action, tcs));
        return await tcs.Task;
    }

    public async ValueTask WriteObjectAsync(
        object? sendToPipeline,
        bool enumerateCollection = false,
        CancellationToken cancellationToken = default)
    {
        TaskCompletionSource tcs = new();
        using var _ = cancellationToken.Register(() => tcs.TrySetCanceled());

        WritePipeline(
            AsyncPipelineType.Output,
            new AsyncOutputRecord(sendToPipeline, enumerateCollection, tcs));
        await tcs.Task;
    }

    public async ValueTask WriteErrorAsync(
        ErrorRecord errorRecord,
        CancellationToken cancellationToken = default)
    {
        TaskCompletionSource tcs = new();
        using var _ = cancellationToken.Register(() => tcs.TrySetCanceled());

        WritePipeline(
            AsyncPipelineType.Error,
            new AsyncErrorRecord(errorRecord, tcs));
        await tcs.Task;
    }

    public void WriteWarning(string message)
        => WritePipeline(AsyncPipelineType.Warning, message);

    public void WriteVerbose(string message)
        => WritePipeline(AsyncPipelineType.Verbose, message);

    public void WriteDebug(string message)
        => WritePipeline(AsyncPipelineType.Debug, message);

    public void WriteInformation(InformationRecord informationRecord)
        => WritePipeline(AsyncPipelineType.Information, informationRecord);

    public void WriteInformation(object messageData, string[] tags)
    {
        string? source = _myInvocation.PSCommandPath;
        if (string.IsNullOrEmpty(source))
        {
            source = _myInvocation.MyCommand.Name;
        }

        InformationRecord infoRecord = new(
            messageData,
            source);
        infoRecord.Tags.AddRange(tags);
        WriteInformation(infoRecord);
    }

    public void WriteHost(
        string message,
        bool noNewLine = false)
    {
        HostInformationMessage msg = new()
        {
            Message = message,
            NoNewLine = noNewLine,
        };
        WriteInformation(msg, ["PSHOST"]);
    }

    public void WriteProgress(ProgressRecord progressRecord)
        => WritePipeline(AsyncPipelineType.Progress, progressRecord);

    private void WritePipeline(AsyncPipelineType type, object? data)
    {
        try
        {
            _pipeline.Add((type, data));
        }
        catch (InvalidOperationException)
        {
            // Thrown if the pipeline has been marked as complete. This indicates
            // that the cmdlet is stopping so we just need to exit out.
            throw new PipelineStoppedException();
        }
    }

    public async Task<T> InvokeScriptAsync<T>(
        string script,
        object?[]? argumentList = null,
        CancellationToken cancellationToken = default)
    {
        TaskCompletionSource<object?> tcs = new();
        WritePipeline(
            AsyncPipelineType.ScriptBlock,
            new ScriptRecord(script, argumentList ?? [], typeof(T), tcs, cancellationToken));

        // InvokeScriptReturnAsIs will handle conversion to T for us.
        return (T)(await tcs.Task)!;
    }
}
