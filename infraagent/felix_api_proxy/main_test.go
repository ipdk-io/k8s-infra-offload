package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestFelixApiProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Felix API Proxy Test Suite")
}

var _ = Describe("Felix API Proxy", func() {
	var _ = Context("preparePipes() should", func() {
		var _ = It("return no error", func() {
			_, _, err := preparePipes(logrus.New(), createPipe)
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot create pipe", func() {
			_, _, err := preparePipes(logrus.New(), createPipeErr)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("connectToSocket() should", func() {
		var _ = It("return no error", func() {
			_, err := connectToSocket(logrus.New(), "dummy", 2, time.Millisecond, dialOk)
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error", func() {
			_, err := connectToSocket(logrus.New(), "dummy", 2, time.Millisecond, dialErr)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("copyData() should", func() {
		var _ = It("return error", func() {
			fr := &fakeReader{}
			fw := &fakeWriter{}
			err := copyData(fw, fr, "destination")
			Expect(err).To(HaveOccurred())
		})
	})
})

func createPipe(fd uintptr, name string) *os.File {
	return &os.File{}
}

func createPipeErr(fd uintptr, name string) *os.File {
	return nil
}

func dialOk(network string, address string) (net.Conn, error) {
	return &net.UnixConn{}, nil
}

func dialErr(network string, address string) (net.Conn, error) {
	return nil, errors.New("Fake error")
}

type fakeWriter struct{}

func (fw *fakeWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("Fake error")
}

type fakeReader struct{}

func (fr *fakeReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("Fake error")
}
