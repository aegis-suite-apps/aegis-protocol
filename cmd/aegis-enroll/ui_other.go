//go:build !windows

package main

import (
	"context"
	"errors"
)

func showEnrollDialog(_ context.Context, _ enrollDialogParams, _ enrollSubmitFn) (enrollOutput, error) {
	return enrollOutput{}, errors.New("aegis-enroll GUI is only supported on Windows")
}
