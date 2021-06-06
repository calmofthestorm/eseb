# Generate a symmetric encryption + signing key

```
eseb keygen
```

# Encrypt and sign

```
echo 'secret message' | ./eseb encrypt -e eseb0::sym::4jBDT/jeZ4sJyGpOvJ8QriGfaqM/ffI5Mhlst8I3DQU=::03418 > crypttext
```

# Decrypt and verify

```
./eseb decrypt -e eseb0::sym::4jBDT/jeZ4sJyGpOvJ8QriGfaqM/ffI5Mhlst8I3DQU=::03418 < crypttext 
```

# Security Considerations

https://twitter.com/martijn_grooten/status/666753211529756672?lang=bg

It writes the output before verifying the integrity of the entire message if
you care.

# Why?

I have my reasons.
