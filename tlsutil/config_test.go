package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/consul/sdk/testutil"
)

func startRPCTLSServer(t *testing.T, c *Configurator) (net.Conn, <-chan error) {
	client, errc, _ := startTLSServer(c.IncomingRPCConfig())
	return client, errc
}

func startALPNRPCTLSServer(t *testing.T, config *Config, alpnProtos []string) (net.Conn, <-chan error) {
	cfg := makeConfigurator(t, *config).IncomingALPNRPCConfig(alpnProtos)
	client, errc, _ := startTLSServer(cfg)
	return client, errc
}

func makeConfigurator(t *testing.T, config Config) *Configurator {
	t.Helper()

	c, err := NewConfigurator(config, nil)
	require.NoError(t, err)

	return c
}

func startTLSServer(tlsConfigServer *tls.Config) (net.Conn, <-chan error, <-chan []*x509.Certificate) {
	errc := make(chan error, 1)
	certc := make(chan []*x509.Certificate, 1)

	client, server := net.Pipe()

	// Use yamux to buffer the reads, otherwise it's easy to deadlock
	muxConf := yamux.DefaultConfig()
	serverSession, _ := yamux.Server(server, muxConf)
	clientSession, _ := yamux.Client(client, muxConf)
	clientConn, _ := clientSession.Open()
	serverConn, _ := serverSession.Accept()

	go func() {
		tlsServer := tls.Server(serverConn, tlsConfigServer)
		if err := tlsServer.Handshake(); err != nil {
			errc <- err
		}
		certc <- tlsServer.ConnectionState().PeerCertificates
		close(errc)

		// Because net.Pipe() is unbuffered, if both sides
		// Close() simultaneously, we will deadlock as they
		// both send an alert and then block. So we make the
		// server read any data from the client until error or
		// EOF, which will allow the client to Close(), and
		// *then* we Close() the server.
		io.Copy(ioutil.Discard, tlsServer)
		tlsServer.Close()
	}()
	return clientConn, errc, certc
}

func loadFile(t *testing.T, path string) string {
	t.Helper()

	data, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestConfigurator_IncomingConfig_Common(t *testing.T) {
	// if this test is failing because of expired certificates
	// use the procedure in test/CA-GENERATION.md
	testCases := map[string]struct {
		setupFn  func(ListenerConfig) Config
		configFn func(*Configurator) *tls.Config
	}{
		"Internal RPC": {
			func(lc ListenerConfig) Config {
				return Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: lc,
					},
				}
			},
			func(c *Configurator) *tls.Config { return c.IncomingRPCConfig() },
		},
		"gRPC": {
			func(lc ListenerConfig) Config { return Config{GRPC: lc} },
			func(c *Configurator) *tls.Config { return c.IncomingGRPCConfig() },
		},
		"HTTPS": {
			func(lc ListenerConfig) Config { return Config{HTTPS: lc} },
			func(c *Configurator) *tls.Config { return c.IncomingHTTPSConfig() },
		},
	}

	for desc, tc := range testCases {
		t.Run(desc, func(t *testing.T) {
			t.Run("MinTLSVersion", func(t *testing.T) {
				cfg := ListenerConfig{
					TLSMinVersion: "tls13",
					CertFile:      "../test/hostname/Alice.crt",
					KeyFile:       "../test/hostname/Alice.key",
				}
				c := makeConfigurator(t, tc.setupFn(cfg))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				tlsClient := tls.Client(client, &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS12,
				})

				err := tlsClient.Handshake()
				require.Error(t, err)
				require.Contains(t, err.Error(), "version not supported")
			})

			t.Run("CipherSuites", func(t *testing.T) {
				cfg := ListenerConfig{
					CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
					CertFile:     "../test/hostname/Alice.crt",
					KeyFile:      "../test/hostname/Alice.key",
				}
				c := makeConfigurator(t, tc.setupFn(cfg))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				tlsClient := tls.Client(client, &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS12, // TLS 1.3 cipher suites are not configurable.
				})
				require.NoError(t, tlsClient.Handshake())

				cipherSuite := tlsClient.ConnectionState().CipherSuite
				require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, cipherSuite)
			})

			t.Run("manually configured certificate is preferred over AutoTLS", func(t *testing.T) {
				// Manually configure Alice's certifcate.
				cfg := ListenerConfig{
					CertFile: "../test/hostname/Alice.crt",
					KeyFile:  "../test/hostname/Alice.key",
				}
				c := makeConfigurator(t, tc.setupFn(cfg))

				// Set Bob's certificate via auto TLS.
				bobCert := loadFile(t, "../test/hostname/Bob.crt")
				bobKey := loadFile(t, "../test/hostname/Bob.key")
				require.NoError(t, c.UpdateAutoTLSCert(bobCert, bobKey))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				// Perform a handshake and check the server presented Alice's certificate.
				tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
				require.NoError(t, tlsClient.Handshake())

				certificates := tlsClient.ConnectionState().PeerCertificates
				require.NotEmpty(t, certificates)
				require.Equal(t, "Alice", certificates[0].Subject.CommonName)

				// Check the server side of the handshake succeded.
				require.NoError(t, <-errc)
			})

			t.Run("AutoTLS certificate is presented if no certificate was configured manually", func(t *testing.T) {
				// No manually configured certificate.
				c := makeConfigurator(t, Config{})

				// Set Bob's certificate via auto TLS.
				bobCert := loadFile(t, "../test/hostname/Bob.crt")
				bobKey := loadFile(t, "../test/hostname/Bob.key")
				require.NoError(t, c.UpdateAutoTLSCert(bobCert, bobKey))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				// Perform a handshake and check the server presented Bobs's certificate.
				tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
				require.NoError(t, tlsClient.Handshake())

				certificates := tlsClient.ConnectionState().PeerCertificates
				require.NotEmpty(t, certificates)
				require.Equal(t, "Bob", certificates[0].Subject.CommonName)

				// Check the server side of the handshake succeded.
				require.NoError(t, <-errc)
			})

			t.Run("VerifyIncoming enabled - successful handshake", func(t *testing.T) {
				cfg := ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				}
				c := makeConfigurator(t, tc.setupFn(cfg))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				tlsClient := tls.Client(client, &tls.Config{
					InsecureSkipVerify: true,
					GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
						cert, err := tls.LoadX509KeyPair("../test/hostname/Bob.crt", "../test/hostname/Bob.key")
						return &cert, err
					},
				})
				require.NoError(t, tlsClient.Handshake())
				require.NoError(t, <-errc)
			})

			t.Run("VerifyIncoming enabled - client provides no certificate", func(t *testing.T) {
				cfg := ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				}
				c := makeConfigurator(t, tc.setupFn(cfg))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
				require.NoError(t, tlsClient.Handshake())

				err := <-errc
				require.Error(t, err)
				require.Contains(t, err.Error(), "client didn't provide a certificate")
			})

			t.Run("VerifyIncoming enabled - client certificate signed by an unknown CA", func(t *testing.T) {
				cfg := ListenerConfig{
					CAFile:         "../test/ca/root.cer",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				}
				c := makeConfigurator(t, tc.setupFn(cfg))

				client, errc, _ := startTLSServer(tc.configFn(c))
				if client == nil {
					t.Fatalf("startTLSServer err: %v", <-errc)
				}

				tlsClient := tls.Client(client, &tls.Config{
					InsecureSkipVerify: true,
					GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
						cert, err := tls.LoadX509KeyPair("../test/hostname/Bob.crt", "../test/hostname/Bob.key")
						return &cert, err
					},
				})
				require.NoError(t, tlsClient.Handshake())

				err := <-errc
				require.Error(t, err)
				require.Contains(t, err.Error(), "signed by unknown authority")
			})
		})
	}
}

func TestConfigurator_IncomingInsecureRPCConfig(t *testing.T) {
	cfg := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:         "../test/hostname/CertAuth.crt",
				CertFile:       "../test/hostname/Alice.crt",
				KeyFile:        "../test/hostname/Alice.key",
				VerifyIncoming: true,
			},
		},
	}

	c := makeConfigurator(t, cfg)

	client, errc, _ := startTLSServer(c.IncomingInsecureRPCConfig())
	if client == nil {
		t.Fatalf("startTLSServer err: %v", <-errc)
	}

	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsClient.Handshake())

	// Check the server side of the handshake succeded.
	require.NoError(t, <-errc)
}

func TestConfigurator_IncomingALPNRPCConfig(t *testing.T) {
	t.Run("successful protocol negotiation", func(t *testing.T) {
		cfg := Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					VerifyIncoming: true,
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
				},
			},
		}
		c := makeConfigurator(t, cfg)

		client, errc, _ := startTLSServer(c.IncomingALPNRPCConfig([]string{"some-protocol"}))
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"some-protocol"},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair("../test/hostname/Bob.crt", "../test/hostname/Bob.key")
				return &cert, err
			},
		})
		require.NoError(t, tlsClient.Handshake())

		require.Equal(t, "some-protocol", tlsClient.ConnectionState().NegotiatedProtocol)

		// Check the server side of the handshake succeded.
		require.NoError(t, <-errc)
	})

	t.Run("client certificate is always required", func(t *testing.T) {
		cfg := Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					VerifyIncoming: false, // this setting is ignored
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
				},
			},
		}
		c := makeConfigurator(t, cfg)

		client, errc, _ := startTLSServer(c.IncomingALPNRPCConfig([]string{"some-protocol"}))
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"some-protocol"},
		})
		require.NoError(t, tlsClient.Handshake())

		err := <-errc
		require.Error(t, err)
		require.Contains(t, err.Error(), "client didn't provide a certificate")
	})

	t.Run("protocol negotiation fails", func(t *testing.T) {
		cfg := Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					VerifyIncoming: true,
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
				},
			},
		}
		c := makeConfigurator(t, cfg)

		client, errc, _ := startTLSServer(c.IncomingALPNRPCConfig([]string{"some-protocol"}))
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"other-protocol"},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair("../test/hostname/Bob.crt", "../test/hostname/Bob.key")
				return &cert, err
			},
		})
		require.Error(t, tlsClient.Handshake())
		require.Error(t, <-errc)
	})
}

func TestConfigurator_OutgoingInternalRPCWrapper(t *testing.T) {
	t.Run("AutoTLS", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				},
			},
		})

		client, errc, _ := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			AutoTLS: true,
		})
		bobCert := loadFile(t, "../test/hostname/Bob.crt")
		bobKey := loadFile(t, "../test/hostname/Bob.key")
		require.NoError(t, clientCfg.UpdateAutoTLSCert(bobCert, bobKey))

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc1", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.NoError(t, err)

		err = <-errc
		require.NoError(t, err)
	})

	t.Run("VerifyOutgoing and a manually configured certificate", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				},
			},
		})

		client, errc, _ := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyOutgoing: true,
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/hostname/CertAuth.crt",
					CertFile: "../test/hostname/Bob.crt",
					KeyFile:  "../test/hostname/Bob.key",
				},
			},
		})

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc1", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.NoError(t, err)

		err = <-errc
		require.NoError(t, err)
	})

	t.Run("outgoing TLS not enabled", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				},
			},
		})

		client, errc, _ := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{})

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		client, err := wrap("dc1", client)
		require.NoError(t, err)
		defer client.Close()

		_, isTLS := client.(*tls.Conn)
		require.False(t, isTLS)
	})

	t.Run("VerifyServerHostname = true", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/client_certs/rootca.crt",
					CertFile: "../test/client_certs/client.crt",
					KeyFile:  "../test/client_certs/client.key",
				},
			},
		})

		client, errc, _ := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyOutgoing:       true,
				VerifyServerHostname: true,
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/client_certs/rootca.crt",
					CertFile: "../test/client_certs/client.crt",
					KeyFile:  "../test/client_certs/client.key",
				},
			},
			Domain: "consul",
		})

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc1", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.Error(t, err)
		require.Regexp(t, `certificate is valid for ([a-z].+) not server.dc1.consul`, err.Error())
	})

	t.Run("VerifyServerHostname = true and incorrect DC name", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/client_certs/rootca.crt",
					CertFile: "../test/client_certs/client.crt",
					KeyFile:  "../test/client_certs/client.key",
				},
			},
		})

		client, errc, _ := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyOutgoing:       true,
				VerifyServerHostname: true,
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/client_certs/rootca.crt",
					CertFile: "../test/client_certs/client.crt",
					KeyFile:  "../test/client_certs/client.key",
				},
			},
			Domain: "consul",
		})

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc2", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.Error(t, err)
		require.Regexp(t, `certificate is valid for ([a-z].+) not server.dc2.consul`, err.Error())
	})

	t.Run("VerifyServerHostname = false", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/client_certs/rootca.crt",
					CertFile: "../test/client_certs/client.crt",
					KeyFile:  "../test/client_certs/client.key",
				},
			},
		})

		client, errc, _ := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyOutgoing:       true,
				VerifyServerHostname: false,
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/client_certs/rootca.crt",
					CertFile: "../test/client_certs/client.crt",
					KeyFile:  "../test/client_certs/client.key",
				},
			},
			Domain: "other",
		})

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc1", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.NoError(t, err)

		// Check the server side of the handshake succeded.
		require.NoError(t, <-errc)
	})

	t.Run("AutoTLS certificate preferred over manually configured certificate", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				},
			},
		})

		client, errc, certc := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyOutgoing:       true,
				VerifyServerHostname: true,
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/hostname/CertAuth.crt",
					CertFile: "../test/hostname/Bob.crt",
					KeyFile:  "../test/hostname/Bob.key",
				},
			},
			Domain: "consul",
		})

		bettyCert := loadFile(t, "../test/hostname/Betty.crt")
		bettyKey := loadFile(t, "../test/hostname/Betty.key")
		require.NoError(t, clientCfg.UpdateAutoTLSCert(bettyCert, bettyKey))

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc1", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.NoError(t, err)

		err = <-errc
		require.NoError(t, err)

		clientCerts := <-certc
		require.NotEmpty(t, clientCerts)
		require.Equal(t, "Betty", clientCerts[0].Subject.CommonName)
	})

	t.Run("manually configured certificate is presented if there's no AutoTLS certificate", func(t *testing.T) {
		serverCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:         "../test/hostname/CertAuth.crt",
					CertFile:       "../test/hostname/Alice.crt",
					KeyFile:        "../test/hostname/Alice.key",
					VerifyIncoming: true,
				},
			},
		})

		client, errc, certc := startTLSServer(serverCfg.IncomingRPCConfig())
		if client == nil {
			t.Fatalf("startTLSServer err: %v", <-errc)
		}

		clientCfg := makeConfigurator(t, Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyOutgoing:       true,
				VerifyServerHostname: true,
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/hostname/CertAuth.crt",
					CertFile: "../test/hostname/Bob.crt",
					KeyFile:  "../test/hostname/Bob.key",
				},
			},
			Domain: "consul",
		})

		wrap := clientCfg.OutgoingInternalRPCWrapper()
		require.NotNil(t, wrap)

		tlsClient, err := wrap("dc1", client)
		require.NoError(t, err)
		defer tlsClient.Close()

		err = tlsClient.(*tls.Conn).Handshake()
		require.NoError(t, err)

		err = <-errc
		require.NoError(t, err)

		clientCerts := <-certc
		require.NotEmpty(t, clientCerts)
		require.Equal(t, "Bob", clientCerts[0].Subject.CommonName)
	})
}

func TestConfigurator_OutgoingInternalRPCWrapper_BadCert(t *testing.T) {
	config := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/ca/root.cer",
				CertFile: "../test/key/ourdomain.cer",
				KeyFile:  "../test/key/ourdomain.key",
			},
			VerifyServerHostname: true,
			VerifyOutgoing:       true,
		},
		Domain: "consul",
	}

	c := makeConfigurator(t, config)

	client, errc := startRPCTLSServer(t, c)
	if client == nil {
		t.Fatalf("startTLSServer err: %v", <-errc)
	}

	wrap := c.OutgoingInternalRPCWrapper()
	tlsClient, err := wrap("dc1", client)
	require.NoError(t, err)

	err = tlsClient.(*tls.Conn).Handshake()
	if _, ok := err.(x509.HostnameError); !ok {
		t.Fatalf("should get hostname err: %v", err)
	}
	tlsClient.Close()

	<-errc
}

func TestConfigurator_outgoingWrapperALPN_OK(t *testing.T) {
	// if this test is failing because of expired certificates
	// use the procedure in test/CA-GENERATION.md
	config := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/hostname/CertAuth.crt",
				CertFile: "../test/hostname/Bob.crt",
				KeyFile:  "../test/hostname/Bob.key",
			},
			VerifyServerHostname: false, // doesn't matter
			VerifyOutgoing:       false, // doesn't matter
		},
		Domain: "consul",
	}

	client, errc := startALPNRPCTLSServer(t, &config, []string{"foo", "bar"})
	if client == nil {
		t.Fatalf("startTLSServer err: %v", <-errc)
	}

	c, err := NewConfigurator(config, nil)
	require.NoError(t, err)
	wrap := c.OutgoingALPNInternalRPCWrapper()
	require.NotNil(t, wrap)

	tlsClient, err := wrap("dc1", "bob", "foo", client)
	require.NoError(t, err)
	defer tlsClient.Close()

	tlsConn := tlsClient.(*tls.Conn)
	cs := tlsConn.ConnectionState()
	require.Equal(t, "foo", cs.NegotiatedProtocol)

	err = <-errc
	require.NoError(t, err)
}

func TestConfigurator_outgoingWrapperALPN_serverHasNoNodeNameInSAN(t *testing.T) {
	// if this test is failing because of expired certificates
	// use the procedure in test/CA-GENERATION.md
	srvConfig := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/hostname/CertAuth.crt",
				CertFile: "../test/hostname/Alice.crt",
				KeyFile:  "../test/hostname/Alice.key",
			},
			VerifyServerHostname: false, // doesn't matter
			VerifyOutgoing:       false, // doesn't matter
		},
		Domain: "consul",
	}

	client, errc := startALPNRPCTLSServer(t, &srvConfig, []string{"foo", "bar"})
	if client == nil {
		t.Fatalf("startTLSServer err: %v", <-errc)
	}

	config := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/hostname/CertAuth.crt",
				CertFile: "../test/hostname/Bob.crt",
				KeyFile:  "../test/hostname/Bob.key",
			},
			VerifyServerHostname: false, // doesn't matter
			VerifyOutgoing:       false, // doesn't matter
		},
		Domain: "consul",
	}

	c, err := NewConfigurator(config, nil)
	require.NoError(t, err)
	wrap := c.OutgoingALPNInternalRPCWrapper()
	require.NotNil(t, wrap)

	_, err = wrap("dc1", "bob", "foo", client)
	require.Error(t, err)
	_, ok := err.(x509.HostnameError)
	require.True(t, ok)
	client.Close()

	<-errc
}

func TestConfigurator_outgoingWrapperALPN_BadDC(t *testing.T) {
	// if this test is failing because of expired certificates
	// use the procedure in test/CA-GENERATION.md
	config := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/hostname/CertAuth.crt",
				CertFile: "../test/hostname/Bob.crt",
				KeyFile:  "../test/hostname/Bob.key",
			},
			VerifyServerHostname: false, // doesn't matter
			VerifyOutgoing:       false, // doesn't matter
		},
		Domain: "consul",
	}

	client, errc := startALPNRPCTLSServer(t, &config, []string{"foo", "bar"})
	if client == nil {
		t.Fatalf("startTLSServer err: %v", <-errc)
	}

	c, err := NewConfigurator(config, nil)
	require.NoError(t, err)
	wrap := c.OutgoingALPNInternalRPCWrapper()

	_, err = wrap("dc2", "bob", "foo", client)
	require.Error(t, err)
	_, ok := err.(x509.HostnameError)
	require.True(t, ok)
	client.Close()

	<-errc
}

func TestConfigurator_outgoingWrapperALPN_BadCert(t *testing.T) {
	config := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/ca/root.cer",
				CertFile: "../test/key/ourdomain.cer",
				KeyFile:  "../test/key/ourdomain.key",
			},
			VerifyServerHostname: false, // doesn't matter
			VerifyOutgoing:       false, // doesn't matter
		},
		Domain: "consul",
	}

	client, errc := startALPNRPCTLSServer(t, &config, []string{"foo", "bar"})
	if client == nil {
		t.Fatalf("startTLSServer err: %v", <-errc)
	}

	c, err := NewConfigurator(config, nil)
	require.NoError(t, err)
	wrap := c.OutgoingALPNInternalRPCWrapper()

	_, err = wrap("dc1", "bob", "foo", client)
	require.Error(t, err)
	_, ok := err.(x509.HostnameError)
	require.True(t, ok)
	client.Close()

	<-errc
}

func TestConfig_ParseCiphers(t *testing.T) {
	testOk := strings.Join([]string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}, ",")
	ciphers := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	v, err := ParseCiphers(testOk)
	require.NoError(t, err)
	if got, want := v, ciphers; !reflect.DeepEqual(got, want) {
		t.Fatalf("got ciphers %#v want %#v", got, want)
	}

	_, err = ParseCiphers("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,cipherX")
	require.Error(t, err)

	v, err = ParseCiphers("")
	require.NoError(t, err)
	require.Equal(t, []uint16{}, v)
}

func TestLoadKeyPair(t *testing.T) {
	type variant struct {
		cert, key string
		shoulderr bool
		isnil     bool
	}
	variants := []variant{
		{"", "", false, true},
		{"bogus", "", false, true},
		{"", "bogus", false, true},
		{"../test/key/ourdomain.cer", "", false, true},
		{"", "../test/key/ourdomain.key", false, true},
		{"bogus", "bogus", true, true},
		{"../test/key/ourdomain.cer", "../test/key/ourdomain.key",
			false, false},
	}
	for i, v := range variants {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			cert, err := loadKeyPair(v.cert, v.key)
			if v.shoulderr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if v.isnil {
				require.Nil(t, cert)
			} else {
				require.NotNil(t, cert)
			}
		})
	}
}

func TestConfig_SpecifyDC(t *testing.T) {
	require.Nil(t, SpecificDC("", nil))
	dcwrap := func(dc string, conn net.Conn) (net.Conn, error) { return nil, nil }
	wrap := SpecificDC("", dcwrap)
	require.NotNil(t, wrap)
	conn, err := wrap(nil)
	require.NoError(t, err)
	require.Nil(t, conn)
}

func TestConfigurator_NewConfigurator(t *testing.T) {
	logger := testutil.Logger(t)
	c, err := NewConfigurator(Config{}, logger)
	require.NoError(t, err)
	require.NotNil(t, c)

	c, err = NewConfigurator(Config{
		InternalRPC: InternalRPCListenerConfig{
			VerifyOutgoing: true,
		},
	}, nil)
	require.Error(t, err)
	require.Nil(t, c)
}

func TestConfigurator_Validation(t *testing.T) {
	const (
		caFile   = "../test/ca/root.cer"
		caPath   = "../test/ca_path"
		certFile = "../test/key/ourdomain.cer"
		keyFile  = "../test/key/ourdomain.key"
	)

	t.Run("empty config", func(t *testing.T) {
		_, err := NewConfigurator(Config{}, nil)
		require.NoError(t, err)
		require.NoError(t, new(Configurator).Update(Config{}))
	})

	t.Run("common fields", func(t *testing.T) {
		type testCase struct {
			config  ListenerConfig
			isValid bool
		}

		testCases := map[string]testCase{
			"invalid TLSMinVersion": {
				ListenerConfig{TLSMinVersion: "tls9"},
				false,
			},
			"default TLSMinVersion": {
				ListenerConfig{TLSMinVersion: ""},
				true,
			},
			"invalid CAFile": {
				ListenerConfig{CAFile: "bogus"},
				false,
			},
			"invalid CAPath": {
				ListenerConfig{CAPath: "bogus"},
				false,
			},
			"invalid CertFile": {
				ListenerConfig{
					CertFile: "bogus",
					KeyFile:  keyFile,
				},
				false,
			},
			"invalid KeyFile": {
				ListenerConfig{
					CertFile: certFile,
					KeyFile:  "bogus",
				},
				false,
			},
			"VerifyIncoming set but no CA": {
				ListenerConfig{
					VerifyIncoming: true,
					CAFile:         "",
					CAPath:         "",
					CertFile:       certFile,
					KeyFile:        keyFile,
				},
				false,
			},
			"VerifyIncoming set but no CertFile": {
				ListenerConfig{
					VerifyIncoming: true,
					CAFile:         caFile,
					CertFile:       "",
					KeyFile:        keyFile,
				},
				false,
			},
			"VerifyIncoming set but no KeyFile": {
				ListenerConfig{
					VerifyIncoming: true,
					CAFile:         caFile,
					CertFile:       certFile,
					KeyFile:        "",
				},
				false,
			},
			"VerifyIncoming + CAFile": {
				ListenerConfig{
					VerifyIncoming: true,
					CAFile:         caFile,
					CertFile:       certFile,
					KeyFile:        keyFile,
				},
				true,
			},
			"VerifyIncoming + CAPath": {
				ListenerConfig{
					VerifyIncoming: true,
					CAPath:         caPath,
					CertFile:       certFile,
					KeyFile:        keyFile,
				},
				true,
			},
			"VerifyIncoming + invalid CAFile": {
				ListenerConfig{
					VerifyIncoming: true,
					CAFile:         "bogus",
					CertFile:       certFile,
					KeyFile:        keyFile,
				},
				false,
			},
			"VerifyIncoming + invalid CAPath": {
				ListenerConfig{
					VerifyIncoming: true,
					CAPath:         "bogus",
					CertFile:       certFile,
					KeyFile:        keyFile,
				},
				false,
			},
		}

		for _, v := range tlsVersions() {
			testCases[fmt.Sprintf("MinTLSVersion(%s)", v)] = testCase{
				ListenerConfig{TLSMinVersion: v},
				true,
			}
		}

		for desc, tc := range testCases {
			for _, ln := range []string{"internal", "grpc", "https"} {
				info := fmt.Sprintf("%s => %s", ln, desc)

				var cfg Config
				switch ln {
				case "internal":
					cfg.InternalRPC.ListenerConfig = tc.config
				case "grpc":
					cfg.GRPC = tc.config
				case "https":
					cfg.HTTPS = tc.config
				default:
					t.Fatalf("unknown listener: %s", ln)
				}

				_, err1 := NewConfigurator(cfg, nil)
				err2 := new(Configurator).Update(cfg)

				if tc.isValid {
					require.NoError(t, err1, info)
					require.NoError(t, err2, info)
				} else {
					require.Error(t, err1, info)
					require.Error(t, err2, info)
				}
			}
		}
	})

	t.Run("internal RPC", func(t *testing.T) {
		for desc, tc := range map[string]struct {
			config  InternalRPCListenerConfig
			isValid bool
		}{
			"VerifyOutgoing + CAFile": {
				InternalRPCListenerConfig{
					VerifyOutgoing: true,
					ListenerConfig: ListenerConfig{CAFile: caFile},
				},
				true,
			},
			"VerifyOutgoing + CAPath": {
				InternalRPCListenerConfig{
					VerifyOutgoing: true,
					ListenerConfig: ListenerConfig{CAPath: caPath},
				},
				true,
			},
			"VerifyOutgoing + CAFile + CAPath": {
				InternalRPCListenerConfig{
					VerifyOutgoing: true,
					ListenerConfig: ListenerConfig{
						CAFile: caFile,
						CAPath: caPath,
					},
				},
				true,
			},
			"VerifyOutgoing but no CA": {
				InternalRPCListenerConfig{
					VerifyOutgoing: true,
					ListenerConfig: ListenerConfig{
						CAFile: "",
						CAPath: "",
					},
				},
				false,
			},
		} {
			cfg := Config{InternalRPC: tc.config}

			_, err1 := NewConfigurator(cfg, nil)
			err2 := new(Configurator).Update(cfg)

			if tc.isValid {
				require.NoError(t, err1, desc)
				require.NoError(t, err2, desc)
			} else {
				require.Error(t, err1, desc)
				require.Error(t, err2, desc)
			}
		}
	})

	t.Run("VerifyIncoming + AutoTLS", func(t *testing.T) {
		cfg := Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					VerifyIncoming: true,
					CAFile:         caFile,
				},
			},
			GRPC: ListenerConfig{
				VerifyIncoming: true,
				CAFile:         caFile,
			},
			HTTPS: ListenerConfig{
				VerifyIncoming: true,
				CAFile:         caFile,
			},
			AutoTLS: true,
		}

		_, err := NewConfigurator(cfg, nil)
		require.NoError(t, err)
		require.NoError(t, new(Configurator).Update(cfg))
	})
}

func TestConfigurator_CommonTLSConfigServerNameNodeName(t *testing.T) {
	type variant struct {
		config Config
		result string
	}
	variants := []variant{
		{config: Config{NodeName: "node", ServerName: "server"},
			result: "server"},
		{config: Config{ServerName: "server"},
			result: "server"},
		{config: Config{NodeName: "node"},
			result: "node"},
	}
	for _, v := range variants {
		c, err := NewConfigurator(v.config, nil)
		require.NoError(t, err)
		tlsConf := c.internalRPCTLSConfig(false)
		require.Empty(t, tlsConf.ServerName)
	}
}

func TestConfigurator_LoadCAs(t *testing.T) {
	type variant struct {
		cafile, capath string
		shouldErr      bool
		isNil          bool
		count          int
	}
	variants := []variant{
		{"", "", false, true, 0},
		{"bogus", "", true, true, 0},
		{"", "bogus", true, true, 0},
		{"", "../test/bin", true, true, 0},
		{"../test/ca/root.cer", "", false, false, 1},
		{"", "../test/ca_path", false, false, 2},
		{"../test/ca/root.cer", "../test/ca_path", false, false, 1},
	}
	for i, v := range variants {
		pems, err1 := LoadCAs(v.cafile, v.capath)
		pool, err2 := newX509CertPool(pems)
		info := fmt.Sprintf("case %d", i)
		if v.shouldErr {
			if err1 == nil && err2 == nil {
				t.Fatal("An error is expected but got nil.")
			}
		} else {
			require.NoError(t, err1, info)
			require.NoError(t, err2, info)
		}
		if v.isNil {
			require.Nil(t, pool, info)
		} else {
			require.NotEmpty(t, pems, info)
			require.NotNil(t, pool, info)
			require.Len(t, pool.Subjects(), v.count, info)
			require.Len(t, pems, v.count, info)
		}
	}
}

func TestConfigurator_InternalRPCMutualTLSCapable(t *testing.T) {
	// if this test is failing because of expired certificates
	// use the procedure in test/CA-GENERATION.md
	t.Run("no ca", func(t *testing.T) {
		config := Config{
			Domain: "consul",
		}
		c, err := NewConfigurator(config, nil)
		require.NoError(t, err)

		require.False(t, c.InternalRPCMutualTLSCapable())
	})

	t.Run("ca and no keys", func(t *testing.T) {
		config := Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile: "../test/hostname/CertAuth.crt",
				},
			},
			Domain: "consul",
		}
		c, err := NewConfigurator(config, nil)
		require.NoError(t, err)

		require.False(t, c.InternalRPCMutualTLSCapable())
	})

	t.Run("ca and manual key", func(t *testing.T) {
		config := Config{
			InternalRPC: InternalRPCListenerConfig{
				ListenerConfig: ListenerConfig{
					CAFile:   "../test/hostname/CertAuth.crt",
					CertFile: "../test/hostname/Bob.crt",
					KeyFile:  "../test/hostname/Bob.key",
				},
			},
			Domain: "consul",
		}
		c, err := NewConfigurator(config, nil)
		require.NoError(t, err)

		require.True(t, c.InternalRPCMutualTLSCapable())
	})

	loadFile := func(t *testing.T, path string) string {
		data, err := ioutil.ReadFile(path)
		require.NoError(t, err)
		return string(data)
	}

	t.Run("autoencrypt ca and no autoencrypt keys", func(t *testing.T) {
		config := Config{
			Domain: "consul",
		}
		c, err := NewConfigurator(config, nil)
		require.NoError(t, err)

		caPEM := loadFile(t, "../test/hostname/CertAuth.crt")
		require.NoError(t, c.UpdateAutoTLSCA([]string{caPEM}))

		require.False(t, c.InternalRPCMutualTLSCapable())
	})

	t.Run("autoencrypt ca and autoencrypt key", func(t *testing.T) {
		config := Config{
			Domain: "consul",
		}
		c, err := NewConfigurator(config, nil)
		require.NoError(t, err)

		caPEM := loadFile(t, "../test/hostname/CertAuth.crt")
		certPEM := loadFile(t, "../test/hostname/Bob.crt")
		keyPEM := loadFile(t, "../test/hostname/Bob.key")
		require.NoError(t, c.UpdateAutoTLSCA([]string{caPEM}))
		require.NoError(t, c.UpdateAutoTLSCert(certPEM, keyPEM))

		require.True(t, c.InternalRPCMutualTLSCapable())
	})
}

func TestConfigurator_UpdateAutoTLSCA_DoesNotPanic(t *testing.T) {
	config := Config{
		Domain: "consul",
	}
	c, err := NewConfigurator(config, hclog.New(nil))
	require.NoError(t, err)

	err = c.UpdateAutoTLSCA([]string{"invalid pem"})
	require.Error(t, err)
}

func TestConfigurator_VerifyIncomingRPC(t *testing.T) {
	c := Configurator{base: &Config{}}
	c.base.InternalRPC.VerifyIncoming = true
	require.True(t, c.VerifyIncomingInternalRPC())
}

func TestConfigurator_IncomingHTTPSConfig(t *testing.T) {

	// compare tls.Config.GetConfigForClient by nil/not-nil, since Go can not compare
	// functions any other way.
	cmpClientFunc := cmp.Comparer(func(x, y func(*tls.ClientHelloInfo) (*tls.Config, error)) bool {
		return (x == nil && y == nil) || (x != nil && y != nil)
	})

	t.Run("default", func(t *testing.T) {
		c, err := NewConfigurator(Config{}, nil)
		require.NoError(t, err)

		cfg := c.IncomingHTTPSConfig()

		expected := &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS10,
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
		}
		assertDeepEqual(t, expected, cfg, cmpTLSConfig, cmpClientFunc)
	})

	t.Run("verify incoming", func(t *testing.T) {
		c := Configurator{base: &Config{}}
		c.base.HTTPS.VerifyIncoming = true

		cfg := c.IncomingHTTPSConfig()

		expected := &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS10,
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		assertDeepEqual(t, expected, cfg, cmpTLSConfig, cmpClientFunc)
	})

}

func TestConfigurator_IncomingExternalGRPCConfig(t *testing.T) {
	c, err := NewConfigurator(Config{
		GRPC: ListenerConfig{
			VerifyIncoming: true,
			CAFile:         "../test/ca/root.cer",
			CertFile:       "../test/key/ourdomain.cer",
			KeyFile:        "../test/key/ourdomain.key",
		},
	}, nil)
	require.NoError(t, err)
	tlsConf := c.IncomingGRPCConfig()
	require.Equal(t, tls.RequireAndVerifyClientCert, tlsConf.ClientAuth)
	require.Empty(t, tlsConf.NextProtos)
	require.Empty(t, tlsConf.ServerName)

	require.NotNil(t, tlsConf.GetConfigForClient)
	tlsConf, err = tlsConf.GetConfigForClient(nil)
	require.NoError(t, err)
	require.Equal(t, tls.RequireAndVerifyClientCert, tlsConf.ClientAuth)
	require.Empty(t, tlsConf.NextProtos)
	require.Empty(t, tlsConf.ServerName)
}

var cmpTLSConfig = cmp.Options{
	cmpopts.IgnoreFields(tls.Config{}, "GetCertificate", "GetClientCertificate"),
	cmpopts.IgnoreUnexported(tls.Config{}),
}

func TestConfigurator_OutgoingTLSConfigForCheck(t *testing.T) {
	type testCase struct {
		name       string
		conf       func() (*Configurator, error)
		skipVerify bool
		serverName string
		expected   *tls.Config
	}

	run := func(t *testing.T, tc testCase) {
		configurator, err := tc.conf()
		require.NoError(t, err)
		c := configurator.OutgoingTLSConfigForCheck(tc.skipVerify, tc.serverName)
		assertDeepEqual(t, tc.expected, c, cmpTLSConfig)
	}

	testCases := []testCase{
		{
			name: "default tls",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{}, nil)
			},
			expected: &tls.Config{},
		},
		{
			name: "default tls, skip verify, no server name",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: ListenerConfig{
							TLSMinVersion: "tls12",
						},
					},
					EnableAgentTLSForChecks: false,
				}, nil)
			},
			skipVerify: true,
			expected:   &tls.Config{InsecureSkipVerify: true},
		},
		{
			name: "default tls, skip verify, default server name",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: ListenerConfig{
							TLSMinVersion: "tls12",
						},
					},
					EnableAgentTLSForChecks: false,
					ServerName:              "servername",
					NodeName:                "nodename",
				}, nil)
			},
			skipVerify: true,
			expected:   &tls.Config{InsecureSkipVerify: true},
		},
		{
			name: "default tls, skip verify, check server name",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: ListenerConfig{
							TLSMinVersion: "tls12",
						},
					},
					EnableAgentTLSForChecks: false,
					ServerName:              "servername",
				}, nil)
			},
			skipVerify: true,
			serverName: "check-server-name",
			expected: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "check-server-name",
			},
		},
		{
			name: "agent tls, default server name",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: ListenerConfig{
							TLSMinVersion: "tls12",
						},
					},
					EnableAgentTLSForChecks: true,
					NodeName:                "nodename",
					ServerName:              "servername",
				}, nil)
			},
			expected: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: "servername",
			},
		},
		{
			name: "agent tls, skip verify, node name for server name",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: ListenerConfig{
							TLSMinVersion: "tls12",
						},
					},
					EnableAgentTLSForChecks: true,
					NodeName:                "nodename",
				}, nil)
			},
			skipVerify: true,
			expected: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				ServerName:         "nodename",
			},
		},
		{
			name: "agent tls, skip verify, with server name override",
			conf: func() (*Configurator, error) {
				return NewConfigurator(Config{
					InternalRPC: InternalRPCListenerConfig{
						ListenerConfig: ListenerConfig{
							TLSMinVersion: "tls12",
						},
					},
					EnableAgentTLSForChecks: true,
					ServerName:              "servername",
				}, nil)
			},
			skipVerify: true,
			serverName: "override",
			expected: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				ServerName:         "override",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func assertDeepEqual(t *testing.T, x, y interface{}, opts ...cmp.Option) {
	t.Helper()
	if diff := cmp.Diff(x, y, opts...); diff != "" {
		t.Fatalf("assertion failed: values are not equal\n--- expected\n+++ actual\n%v", diff)
	}
}

func TestConfigurator_OutgoingRPCConfig(t *testing.T) {
	c := &Configurator{base: &Config{}}
	require.Nil(t, c.OutgoingInternalRPCConfig())

	c, err := NewConfigurator(Config{
		InternalRPC: InternalRPCListenerConfig{
			VerifyOutgoing: true,
			ListenerConfig: ListenerConfig{
				CAFile: "../test/ca/root.cer",
			},
		},
	}, nil)
	require.NoError(t, err)

	tlsConf := c.OutgoingInternalRPCConfig()
	require.NotNil(t, tlsConf)
	require.Equal(t, tls.NoClientCert, tlsConf.ClientAuth)
	require.True(t, tlsConf.InsecureSkipVerify)
	require.Empty(t, tlsConf.NextProtos)
	require.Empty(t, tlsConf.ServerName)
}

func TestConfigurator_OutgoingALPNRPCConfig(t *testing.T) {
	c := &Configurator{base: &Config{}}
	require.Nil(t, c.outgoingALPNRPCConfig())

	c, err := NewConfigurator(Config{
		InternalRPC: InternalRPCListenerConfig{
			VerifyOutgoing: false, // ignored, assumed true
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/ca/root.cer",
				CertFile: "../test/key/ourdomain.cer",
				KeyFile:  "../test/key/ourdomain.key",
			},
		},
	}, nil)
	require.NoError(t, err)

	tlsConf := c.outgoingALPNRPCConfig()
	require.NotNil(t, tlsConf)
	require.Equal(t, tls.RequireAndVerifyClientCert, tlsConf.ClientAuth)
	require.False(t, tlsConf.InsecureSkipVerify)
	require.Empty(t, tlsConf.NextProtos)
	require.Empty(t, tlsConf.ServerName)
}

func TestConfigurator_OutgoingRPCWrapper(t *testing.T) {
	c := &Configurator{base: &Config{}}
	wrapper := c.OutgoingInternalRPCWrapper()
	require.NotNil(t, wrapper)
	conn := &net.TCPConn{}
	cWrap, err := wrapper("", conn)
	require.NoError(t, err)
	require.Equal(t, conn, cWrap)

	c, err = NewConfigurator(Config{
		InternalRPC: InternalRPCListenerConfig{
			VerifyOutgoing: true,
			ListenerConfig: ListenerConfig{
				CAFile: "../test/ca/root.cer",
			},
		},
	}, nil)
	require.NoError(t, err)

	wrapper = c.OutgoingInternalRPCWrapper()
	require.NotNil(t, wrapper)
	cWrap, err = wrapper("", conn)
	require.EqualError(t, err, "invalid argument")
	require.NotEqual(t, conn, cWrap)
}

func TestConfigurator_OutgoingALPNRPCWrapper(t *testing.T) {
	c := &Configurator{base: &Config{}}
	wrapper := c.OutgoingInternalRPCWrapper()
	require.NotNil(t, wrapper)
	conn := &net.TCPConn{}
	cWrap, err := wrapper("", conn)
	require.NoError(t, err)
	require.Equal(t, conn, cWrap)

	c, err = NewConfigurator(Config{
		InternalRPC: InternalRPCListenerConfig{
			VerifyOutgoing: true,
			ListenerConfig: ListenerConfig{
				CAFile: "../test/ca/root.cer",
			},
		},
	}, nil)
	require.NoError(t, err)

	wrapper = c.OutgoingInternalRPCWrapper()
	require.NotNil(t, wrapper)
	cWrap, err = wrapper("", conn)
	require.EqualError(t, err, "invalid argument")
	require.NotEqual(t, conn, cWrap)
}

// TODO: this should probably be combined with validation test.
func TestConfigurator_UpdateChecks(t *testing.T) {
	c, err := NewConfigurator(Config{}, nil)
	require.NoError(t, err)
	require.NoError(t, c.Update(Config{}))
	require.Error(t, c.Update(Config{InternalRPC: InternalRPCListenerConfig{VerifyOutgoing: true}}))
	require.Error(t, c.Update(Config{InternalRPC: InternalRPCListenerConfig{ListenerConfig: ListenerConfig{VerifyIncoming: true, CAFile: "../test/ca/root.cer"}}}))
	require.False(t, c.base.InternalRPC.VerifyIncoming)
	require.False(t, c.base.InternalRPC.VerifyOutgoing)
	require.Equal(t, uint64(2), c.version)
}

func TestConfigurator_UpdateSetsStuff(t *testing.T) {
	c, err := NewConfigurator(Config{}, nil)
	require.NoError(t, err)
	require.Nil(t, c.internalRPC.combinedCAPool)
	require.Nil(t, c.internalRPC.cert)
	require.Equal(t, c.base, &Config{})
	require.Equal(t, uint64(1), c.version)

	require.Error(t, c.Update(Config{InternalRPC: InternalRPCListenerConfig{VerifyOutgoing: true}}))
	require.Equal(t, uint64(1), c.version)

	// TODO: Check this.
	config := Config{
		InternalRPC: InternalRPCListenerConfig{
			ListenerConfig: ListenerConfig{
				CAFile:   "../test/ca/root.cer",
				CertFile: "../test/key/ourdomain.cer",
				KeyFile:  "../test/key/ourdomain.key",
			},
		},
	}
	require.NoError(t, c.Update(config))
	require.NotNil(t, c.internalRPC.combinedCAPool)
	require.Len(t, c.internalRPC.combinedCAPool.Subjects(), 1)
	require.NotNil(t, c.internalRPC.cert)
	require.Equal(t, c.base, &config)
	require.Equal(t, uint64(2), c.version)
}

func TestConfigurator_ServerNameOrNodeName(t *testing.T) {
	c := Configurator{base: &Config{}}
	type variant struct {
		server, node, expected string
	}
	variants := []variant{
		{"", "", ""},
		{"a", "", "a"},
		{"", "b", "b"},
		{"a", "b", "a"},
	}
	for _, v := range variants {
		c.base.ServerName = v.server
		c.base.NodeName = v.node
		require.Equal(t, v.expected, c.serverNameOrNodeName())
	}
}

func TestConfigurator_VerifyServerHostname(t *testing.T) {
	c := Configurator{base: &Config{}}
	require.False(t, c.VerifyServerHostname())

	c.base.InternalRPC.VerifyServerHostname = true
	c.autoTLS.verifyServerHostname = false
	require.True(t, c.VerifyServerHostname())

	c.base.InternalRPC.VerifyServerHostname = false
	c.autoTLS.verifyServerHostname = true
	require.True(t, c.VerifyServerHostname())

	c.base.InternalRPC.VerifyServerHostname = true
	c.autoTLS.verifyServerHostname = true
	require.True(t, c.VerifyServerHostname())
}

func TestConfigurator_AutoEncryptCert(t *testing.T) {
	c := Configurator{base: &Config{}}
	require.Nil(t, c.AutoEncryptCert())

	cert, err := loadKeyPair("../test/key/something_expired.cer", "../test/key/something_expired.key")
	require.NoError(t, err)
	c.autoTLS.cert = cert
	require.Equal(t, int64(1561561551), c.AutoEncryptCert().NotAfter.Unix())

	cert, err = loadKeyPair("../test/key/ourdomain.cer", "../test/key/ourdomain.key")
	require.NoError(t, err)
	c.autoTLS.cert = cert
	require.Equal(t, int64(4679716209), c.AutoEncryptCert().NotAfter.Unix())
}

func TestConfigurator_AuthorizeInternalRPCServerConn(t *testing.T) {
	caPEM, caPK, err := GenerateCA(CAOpts{Days: 5, Domain: "consul"})
	require.NoError(t, err)

	dir := testutil.TempDir(t, "ca")
	caPath := filepath.Join(dir, "ca.pem")
	err = ioutil.WriteFile(caPath, []byte(caPEM), 0600)
	require.NoError(t, err)

	// TODO: fix this comment.
	//
	// Cert and key are not used, but required to get past validateConfig
	signer, err := ParseSigner(caPK)
	require.NoError(t, err)
	pub, pk, err := GenerateCert(CertOpts{
		Signer: signer,
		CA:     caPEM,
	})
	require.NoError(t, err)
	certFile := filepath.Join("cert.pem")
	err = ioutil.WriteFile(certFile, []byte(pub), 0600)
	require.NoError(t, err)
	keyFile := filepath.Join("cert.key")
	err = ioutil.WriteFile(keyFile, []byte(pk), 0600)
	require.NoError(t, err)

	cfg := Config{
		InternalRPC: InternalRPCListenerConfig{
			VerifyServerHostname: true,
			ListenerConfig: ListenerConfig{
				VerifyIncoming: true,
				CAFile:         caPath,
				CertFile:       certFile,
				KeyFile:        keyFile,
			},
		},
		Domain: "consul",
	}
	c, err := NewConfigurator(cfg, hclog.New(nil))
	require.NoError(t, err)

	t.Run("wrong DNSName", func(t *testing.T) {
		signer, err := ParseSigner(caPK)
		require.NoError(t, err)

		pem, _, err := GenerateCert(CertOpts{
			Signer:      signer,
			CA:          caPEM,
			Name:        "server.dc1.consul",
			Days:        5,
			DNSNames:    []string{"this-name-is-wrong", "localhost"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		require.NoError(t, err)

		s := fakeTLSConn{
			state: tls.ConnectionState{
				VerifiedChains:   [][]*x509.Certificate{certChain(t, pem, caPEM)},
				PeerCertificates: certChain(t, pem, caPEM),
			},
		}
		err = c.AuthorizeInternalRPCServerConn("dc1", s)
		testutil.RequireErrorContains(t, err, "is valid for this-name-is-wrong, localhost, not server.dc1.consul")
	})

	t.Run("wrong CA", func(t *testing.T) {
		caPEM, caPK, err := GenerateCA(CAOpts{Days: 5, Domain: "consul"})
		require.NoError(t, err)

		dir := testutil.TempDir(t, "other")
		caPath := filepath.Join(dir, "ca.pem")
		err = ioutil.WriteFile(caPath, []byte(caPEM), 0600)
		require.NoError(t, err)

		signer, err := ParseSigner(caPK)
		require.NoError(t, err)

		pem, _, err := GenerateCert(CertOpts{
			Signer:      signer,
			CA:          caPEM,
			Name:        "server.dc1.consul",
			Days:        5,
			DNSNames:    []string{"server.dc1.consul", "localhost"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		require.NoError(t, err)

		s := fakeTLSConn{
			state: tls.ConnectionState{
				VerifiedChains:   [][]*x509.Certificate{certChain(t, pem, caPEM)},
				PeerCertificates: certChain(t, pem, caPEM),
			},
		}
		err = c.AuthorizeInternalRPCServerConn("dc1", s)
		testutil.RequireErrorContains(t, err, "signed by unknown authority")
	})

	t.Run("missing ext key usage", func(t *testing.T) {
		signer, err := ParseSigner(caPK)
		require.NoError(t, err)

		pem, _, err := GenerateCert(CertOpts{
			Signer:      signer,
			CA:          caPEM,
			Name:        "server.dc1.consul",
			Days:        5,
			DNSNames:    []string{"server.dc1.consul", "localhost"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		})
		require.NoError(t, err)

		s := fakeTLSConn{
			state: tls.ConnectionState{
				VerifiedChains:   [][]*x509.Certificate{certChain(t, pem, caPEM)},
				PeerCertificates: certChain(t, pem, caPEM),
			},
		}
		err = c.AuthorizeInternalRPCServerConn("dc1", s)
		testutil.RequireErrorContains(t, err, "certificate specifies an incompatible key usage")
	})

	t.Run("disabled by verify_incoming_rpc", func(t *testing.T) {
		cfg := Config{
			InternalRPC: InternalRPCListenerConfig{
				VerifyServerHostname: true,
				ListenerConfig: ListenerConfig{
					VerifyIncoming: false,
					CAFile:         caPath,
				},
			},
			Domain: "consul",
		}
		c, err := NewConfigurator(cfg, hclog.New(nil))
		require.NoError(t, err)

		s := fakeTLSConn{}
		err = c.AuthorizeInternalRPCServerConn("dc1", s)
		require.NoError(t, err)
	})

}

type fakeTLSConn struct {
	state tls.ConnectionState
}

func (f fakeTLSConn) ConnectionState() tls.ConnectionState {
	return f.state
}

func certChain(t *testing.T, certs ...string) []*x509.Certificate {
	t.Helper()

	result := make([]*x509.Certificate, 0, len(certs))

	for i, c := range certs {
		cert, err := parseCert(c)
		require.NoError(t, err, "cert %d", i)
		result = append(result, cert)
	}
	return result
}

func TestConfig_tlsVersions(t *testing.T) {
	require.Equal(t, []string{"tls10", "tls11", "tls12", "tls13"}, tlsVersions())
	expected := "tls10, tls11, tls12, tls13"
	require.Equal(t, expected, strings.Join(tlsVersions(), ", "))
}

func TestConfigurator_GRPCTLSEnabled(t *testing.T) {
	t.Run("certificate manually configured", func(t *testing.T) {
		c := makeConfigurator(t, Config{
			GRPC: ListenerConfig{
				CertFile: "../test/hostname/Alice.crt",
				KeyFile:  "../test/hostname/Alice.key",
			},
		})
		require.True(t, c.GRPCTLSEnabled())
	})

	t.Run("AutoTLS", func(t *testing.T) {
		c := makeConfigurator(t, Config{})

		bobCert := loadFile(t, "../test/hostname/Bob.crt")
		bobKey := loadFile(t, "../test/hostname/Bob.key")
		require.NoError(t, c.UpdateAutoTLSCert(bobCert, bobKey))

		require.True(t, c.GRPCTLSEnabled())
	})

	t.Run("no certificate", func(t *testing.T) {
		c := makeConfigurator(t, Config{})
		require.False(t, c.GRPCTLSEnabled())
	})
}

// TODO: Test CA stuff.
