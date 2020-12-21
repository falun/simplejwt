# simplejwt

The goal here was to get an idiot's interface to JWT. This is mostly there but
the underlying library I'm using to do JWT juggling/validation has an outstanding
bug vs ECDSA that makes it not worth continuing.

**tl;dr** Use [square's library](https://godoc.org/gopkg.in/square/go-jose.v2) instead.