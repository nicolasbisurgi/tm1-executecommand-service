package command

// FakeSync is a programmable SyncExecutor for tests. Construct with an OnRun
// closure that decides what to return for each Command — typically used to
// canned responses or simulated failures.
type FakeSync struct {
	OnRun func(cmd Command) (Result, error)
}

func (f *FakeSync) Run(cmd Command) (Result, error) {
	if f.OnRun == nil {
		return Result{}, nil
	}
	return f.OnRun(cmd)
}

// FakeAsync is a programmable AsyncExecutor for tests.
type FakeAsync struct {
	OnStart func(cmd Command) (Handle, error)
}

func (f *FakeAsync) Start(cmd Command) (Handle, error) {
	if f.OnStart == nil {
		return Handle{}, nil
	}
	return f.OnStart(cmd)
}
