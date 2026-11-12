with SMB.Crypto;

--  The SMB 3.1.1 key derivation (MS-SMB2 3.1.4.2, 3.2.5.3.1): NIST SP 800-108
--  in counter mode with HMAC-SHA256 as the PRF, a 32-bit counter (r = 32)
--  and an output length L of 128 or 256 bits, so a single PRF block,
--  truncated to 16 bytes when L = 128:
--
--     HMAC-SHA256 (Session_Key,
--                  00000001 || Label || 00 || Preauth_Hash || L)
--
--  with L as 32 bits big-endian: 00000080 or 00000100. L is part of the
--  PRF input, so the 16 bytes of a 128-bit key are not the first 16 bytes
--  of the 256-bit key with the same label.
--
--  Label includes its terminating NUL. Session_Key is the 16-byte NTLM
--  ExportedSessionKey and Preauth_Hash the session's final SHA-512 preauth
--  integrity hash value. Only the three labels the 3.1.1 client needs
--  exist, so a caller cannot pass a label without its NUL, an SMB 3.0 label
--  or the ApplicationKey label.
--
--  The proof covers run-time safety, and the types fix every length.
--  Microsoft's worked examples and the comparison with Python's
--  cryptography cover the values. HMAC_SHA256_Finish wipes the HMAC
--  context; nothing else is wiped: not the 32-byte HMAC output in Derive's
--  frame, and not the copies the compiler leaves on the stack.
package SMB.KDF is
   pragma SPARK_Mode (On);

   --  The keys of a client session, named as MS-SMB2 names Session's
   --  SigningKey, EncryptionKey and DecryptionKey:
   --    Signing     "SMBSigningKey\0"    signs and verifies messages
   --    Encryption  "SMBC2SCipherKey\0"  client to server
   --    Decryption  "SMBS2CCipherKey\0"  server to client
   type Key_Purpose is (Signing, Encryption, Decryption);

   --  L = 128: the key for AES-128 (CMAC signing, and AES-128-CCM or
   --  AES-128-GCM encryption).
   function Derive
     (Session_Key : SMB.Crypto.Digest_128;
      Purpose : Key_Purpose;
      Preauth_Hash : SMB.Crypto.Digest_512) return SMB.Crypto.Digest_128;

   --  L = 256: the key for AES-256 (AES-256-CCM or AES-256-GCM encryption).
   function Derive_256
     (Session_Key : SMB.Crypto.Digest_128;
      Purpose : Key_Purpose;
      Preauth_Hash : SMB.Crypto.Digest_512) return SMB.Crypto.Digest_256;
end SMB.KDF;
