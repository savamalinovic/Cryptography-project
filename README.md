# Cryptography-project

Short JavaFX application that demonstrates an encrypted file system (EFS). The project supports user creation, login with passwords and X.509 certificates, file encryption, digital signature verification, and encrypted file sharing between users.

## Features

- Admin and user account creation
- Password hashing with PBKDF2, BCrypt, or Argon2id
- X.509 certificate validation with CA signature and CRL checks
- File encryption with AES-GCM
- Encrypted file keys stored in `keys/<user>/`
- Digital signing and file integrity verification
- File sharing through `shared/` and `shared_metadata/`
- JavaFX view of user and shared directories

## Technologies

- Java
- Maven
- JavaFX 17
- Bouncy Castle
- BCrypt
- Argon2 JVM
- OpenSSL for generating user certificates

## Structure

The main Maven project is located in the `filesystem/` folder.

- `src/main/java/com/main/` - JavaFX application and file system view
- `src/main/java/crypto/` - encryption, signatures, passwords, and sharing
- `certificates/` - CA, user certificates, and private keys
- `efs/` - user encrypted files
- `keys/` - encrypted file keys and signatures
- `shared/` and `shared_metadata/` - shared files and metadata

## Running

Java, Maven, and OpenSSL are required. The application uses relative paths, so it should be started from the `filesystem/` folder.

```powershell
cd filesystem
mvn javafx:run
```

Tests can be run with:

```powershell
mvn test
```

Note: the OpenSSL path in the code is set to `C:\Program Files\OpenSSL-Win64\bin\openssl.exe`, so it may need to be adjusted for the local installation.

## Short Repository Description

JavaFX encrypted file system application with user certificates, AES-GCM encryption, digital signatures, and file sharing between users.
