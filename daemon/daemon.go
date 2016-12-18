// Common daemon code

package daemon

// Start and return a wait and stop function
type DaemonWorker func() (func(), func())
