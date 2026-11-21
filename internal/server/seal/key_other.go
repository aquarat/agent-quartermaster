//go:build !linux

package seal

import "errors"

func keyPage() ([]byte, error) { return nil, errors.New("seal: locked key pages require Linux") }
func freePage([]byte)          { panic("seal: unexpected key page") }
