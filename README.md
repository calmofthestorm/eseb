# eseb

## Usage

### Generate keys

Generate a symmetric encryption + signing key:

```
eseb keygen --symmetric
```

Generate a Snow keypair (prints private + public):

```
eseb keygen --snow
```

### Encrypt and sign

Symmetric encryption with a key string:

```
echo 'secret message' | eseb encrypt -e eseb0::sym::4jBDT/jeZ4sJyGpOvJ8QriGfaqM/ffI5Mhlst8I3DQU=::03418 > crypttext
```

Use a key file:

```
echo 'secret message' | eseb encrypt -e ./sym.key > crypttext
```

Legacy record format (Record32):

```
echo 'secret message' | eseb encrypt -e ./sym.key --legacy > crypttext
```

Enable compression:

```
echo 'secret message' | eseb encrypt -e ./sym.key --compress > crypttext
```

### Decrypt and verify

Symmetric decryption with a key string:

```
eseb decrypt -e eseb0::sym::4jBDT/jeZ4sJyGpOvJ8QriGfaqM/ffI5Mhlst8I3DQU=::03418 < crypttext
```

Use a key file:

```
eseb decrypt -e ./sym.key < crypttext
```

Legacy record format (Record32):

```
eseb decrypt -e ./sym.key --legacy < crypttext
```

Enable decompression:

```
eseb decrypt -e ./sym.key --compress < crypttext
```

## Security Considerations

https://twitter.com/martijn_grooten/status/666753211529756672?lang=bg

Malicious input can probably DoS due to dependency on eseb.

It writes the output before verifying the integrity of the entire message if
you care.

## Why?

I have my reasons.
