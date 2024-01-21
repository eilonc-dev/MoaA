package main

import (
	"fmt"
	"moaa/pkg/sysinfo"
	""
)

func main() {
	fmt.Println("Hello, World!")
	info := sysinfo.GetSystemInfo()
    // Now you can use the info variable to access the system information.
    fmt.Println("OS:", info.OS)
    fmt.Println("Architecture:", info.Arch)
    fmt.Println("CPUs:", info.CPUs)
    fmt.Println("Kernel Version:", info.KernelVersion)
    fmt.Println("Go Version:", info.GoVersion)
    fmt.Println("Hostname:", info.Hostname)
    fmt.Println("IP:", info.IP)
    fmt.Println("MAC:", info.MAC)
    fmt.Println("FQDN:", info.FQDN)
    fmt.Println("Uptime:", info.Uptime)
    fmt.Println("Last Boot Time:", info.LastBootTime)
    fmt.Println("Processes:", info.Processes)
    fmt.Println("Users:", info.Users)
    fmt.Println("Logged In Users:", info.LoggedInUsers)
    fmt.Println("System Load:", info.SystemLoad)
    fmt.Println("CPU Usage:", info.CPUUsage)
    fmt.Println("Memory Usage:", info.MemoryUsage)
    fmt.Println("Disk Usage:", info.DiskUsage)
    fmt.Println("File Descriptors:", info.FileDescriptors)
    fmt.Println("Platform:", info.Platform)
    fmt.Println("Platform Family:", info.PlatformFamily)
    fmt.Println("Platform Version:", info.PlatformVersion)

    fmt.Println("Running Containers:")
    for _, container := range info.RunningContainers {
        fmt.Println("\t", container)
    }

    fmt.Println("Installed Packages:")
    for _, pkg := range info.InstalledPackages {
        fmt.Println("\t", pkg)
    }
}