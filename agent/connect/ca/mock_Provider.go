// Code generated by mockery v1.0.0. DO NOT EDIT.

package ca

import mock "github.com/stretchr/testify/mock"
import x509 "crypto/x509"

// MockProvider is an autogenerated mock type for the Provider type
type MockProvider struct {
	mock.Mock
}

// ActiveIntermediate provides a mock function with given fields:
func (_m *MockProvider) ActiveIntermediate() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ActiveRoot provides a mock function with given fields:
func (_m *MockProvider) ActiveRoot() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Cleanup provides a mock function with given fields:
func (_m *MockProvider) Cleanup() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Configure provides a mock function with given fields: clusterID, datacenterName, dnsDomain, isRoot, rawConfig
func (_m *MockProvider) Configure(clusterId string, datacenterName string, dnsDomain string, isRoot bool, rawConfig map[string]interface{}) error {
	ret := _m.Called(clusterId, datacenterName, dnsDomain, isRoot, rawConfig)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string, bool, map[string]interface{}) error); ok {
		r0 = rf(clusterId, datacenterName, dnsDomain, isRoot, rawConfig)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CrossSignCA provides a mock function with given fields: _a0
func (_m *MockProvider) CrossSignCA(_a0 *x509.Certificate) (string, error) {
	ret := _m.Called(_a0)

	var r0 string
	if rf, ok := ret.Get(0).(func(*x509.Certificate) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*x509.Certificate) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateIntermediate provides a mock function with given fields:
func (_m *MockProvider) GenerateIntermediate() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateIntermediateCSR provides a mock function with given fields:
func (_m *MockProvider) GenerateIntermediateCSR() (string, error) {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateRoot provides a mock function with given fields:
func (_m *MockProvider) GenerateRoot() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetIntermediate provides a mock function with given fields: intermediatePEM, rootPEM
func (_m *MockProvider) SetIntermediate(intermediatePEM string, rootPEM string) error {
	ret := _m.Called(intermediatePEM, rootPEM)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(intermediatePEM, rootPEM)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Sign provides a mock function with given fields: _a0
func (_m *MockProvider) Sign(_a0 *x509.CertificateRequest) (string, error) {
	ret := _m.Called(_a0)

	var r0 string
	if rf, ok := ret.Get(0).(func(*x509.CertificateRequest) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*x509.CertificateRequest) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SignIntermediate provides a mock function with given fields: _a0
func (_m *MockProvider) SignIntermediate(_a0 *x509.CertificateRequest) (string, error) {
	ret := _m.Called(_a0)

	var r0 string
	if rf, ok := ret.Get(0).(func(*x509.CertificateRequest) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*x509.CertificateRequest) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
