package handler

import "os/exec"

func RunPing(host string) error {
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	return cmd.Run()
}
