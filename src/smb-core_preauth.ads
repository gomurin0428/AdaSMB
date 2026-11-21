with SMB.Crypto;
with SMB.Spec.SHA2;

--  The SMB 3.1.1 preauth integrity hash (MS-SMB2 3.2.5.2 and 3.2.5.3.1),
--  with SHA-512, the only algorithm we offer:
--
--     H := 64 zero bytes
--     H := SHA-512 (H || NEGOTIATE request)             -- the connection
--     H := SHA-512 (H || NEGOTIATE response)
--     H := SHA-512 (H || SESSION_SETUP request 1)       -- the session
--     H := SHA-512 (H || SESSION_SETUP response 1)
--     H := SHA-512 (H || SESSION_SETUP request 2)
--
--  Each message is the whole SMB2 message from its header on, without the
--  four-byte TCP framing. The final, successful SESSION_SETUP response is
--  not hashed, and the session's final H is SMB.KDF's Preauth_Hash.
--  Update's postcondition states the step with FIPS 180-4's SHA-512
--  (SMB.Spec.SHA2); Microsoft's worked examples cover the sequence.
package SMB.Core_Preauth is
   pragma SPARK_Mode (On);

   subtype Hash_Value is SMB.Crypto.Digest_512;

   Initial : constant Hash_Value := (others => 0);

   --  The postcondition is proved and never run: the specification
   --  recurses over the message, and the stack check rejects recursion
   --  reachable from SMB.Client in every build.
   pragma Assertion_Policy (Post => Ignore);

   --  Value := SHA-512 (Value || Message).
   procedure Update (Value : in out Hash_Value; Message : SMB.Bytes)
   with Pre => Message'Length <= SMB.Maximum_Frame_Size,
     Post => Value = SMB.Spec.SHA2.SHA512 (Value'Old & Message);

end SMB.Core_Preauth;
