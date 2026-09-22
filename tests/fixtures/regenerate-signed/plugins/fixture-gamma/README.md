# Fixture Gamma

A staging listing, owned by an account with no publisher record.

## Two branches in one listing

`staging: true` means the flat compatibility projection must emit an empty
`download_url` and an empty `platform_downloads`: a client that only understands
the flat fields cannot verify what it would download, so the only safe thing to
hand it is nothing.

And `someone-else` has no file under `publishers/`, so this entry must carry no
`publisher` key at all. The absence is what a store reads as "no badge"; a
client that badged on the field merely being present would badge everybody, so
the regeneration has to be able to produce an entry without one.
