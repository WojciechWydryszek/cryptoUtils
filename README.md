# CryptoUtils

The function of this library is encript messages.

Using the file *hash.properties*, inside it we are define all parameters for encript the message, for exemple the hash algorithm, use or no salt, etc.

He have methdots for encrypt/decrypt (symmetric encrypt) and sign/verify (asymmetric encrypt).

For encrypt message is need to create CryptoUtils object (is not static class), parameters for encrypt is the message in byte[] and one password in formate String returning this message in byte[], and for decrypt is the same byte[] returning encrypt and the same password.

For sign need pass message in byte[] returning signature in byte[]. If is need we can use verify medoth passing one message, returning signature from sign and certificate (all in byte[])
