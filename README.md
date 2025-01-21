# Password_Vault

The overarching goal of this programming project is to imple-
ment such a working password manager in Python using a cryptographic library called pycryptodome. The other goal of the project is to provide hands-on
training to students regarding how to effectively use cryptographic constructs to achieve better
security.

- Design Principle
Roughly, existing password managers or vaults can be categorized into the following three dimen-
sions: (1) Storing the vault or encrypted password file in the cloud, local storage, or both; (2)
Recoverability of the master password; (3) Availability of the autofill functionality.
The password vault or manager you are going to implement will have the following features: (a)
the encrypted password vault will be stored only in the local storage; (b) there is no Recoverability
of the master passwords (if you forget the master password then you will lose access to the vault);
(c) there is no auto-filling feature; (d) one does not need to open an account to use the vault.
To implement such a password vault, one has to consider the following main things: (1) To
ensure that the password vault is secure (both confidentiality and integrity), the password vault file
will never be stored in local storage in plaintext; (2) how does one store the symmetric keys that
are used to encrypt and integrity-protect the password vault file; (3) how does the vault operate
without requiring the users to open up an account.

Symmetric Key Storage Problem. Instead of storing the key in the disk, the key will be
generated dynamically from the user’s master password in memory. For this, you will use the
scrypt function from the pycryptodome library

User account problem. Instead of using a database where the user password is stored, the
password manager takes a different approach because then security boils down to protecting the
database where user information is stored. The vault essentially hashes the master user account us-
ing the sha256 function from the pycryptodome library (see https://pycryptodome.readthedocs.
io/en/latest/src/hash/sha256.html#sha-256) and then names the password vault file the re-
sulting digest. To essentially see whether the current user has an account already, you calculate
the SHA256 hash of the master username and see whether there is a file in that name. If a file
is present already, then it suggests that user already has an account. Otherwise, the user will be
presented to create a new account by creating the file.

Format of a password vault in plaintext. In plaintext, a password vault file can be viewed as
a list, where each element of the list appears in a single line. Each of these lines has the following
format: ⟨username : password : domain⟩. As you can see, the username, password, and domain
name fields are separated by the “:” character. Hence, username, password, or domain name fields
cannot have the “:” character in them.
Before encrypting the plaintext vault file in memory and then storing it in a file, one should
prepend the magic string “101010101010101010102020202020202020202030303030303030303030”
followed by a new line character to the list of ⟨username : password : domain⟩.

The reason for magic string. One may wonder what is the goal of the magic string discussed
just above. This is to protect against the following situation. Consider a user who opened an account
(i.e., created a password vault file) with the username “random” and password “doublerandom”.
Another user came in and chose the username “random” and password “triplerandom”. In case
of the second user, your password vault program would find a corresponding file because the first
user used the same account number. When you try to decrypt the file of the first user using the
key derived from the password “triplerandom”, obviously the decryption will fail. However, how
would one programmatically figure out that the decryption failed. The best way to figure out is
that whether the decrypted file has the magic string in the first line. If it has the magic string,
then you can safely conclude that the file was successfully decrypted. Otherwise, you can conclude
that one of the following situation occurred without being able to tell exactly which one: (1) the
user has forgotten the master password ; (2) the user currently attempting to log in is a new user.

