--  SMB 3.1.1 negotiation (MS-SMB2 2.2.3, 2.2.4 and 3.2.5.2; the profile is in
--  docs/smb3-design.md): the NEGOTIATE request body with its two negotiate
--  contexts, and the checks on the negotiate contexts of a response that
--  selected 3.1.1. Packet offsets count from the start of the SMB2 header, as
--  the protocol's offset fields do.
package SMB.Core_Negotiate is
   pragma SPARK_Mode (On);

   subtype Guid_Bytes is SMB.Bytes (0 .. 15);
   subtype Salt_Bytes is SMB.Bytes (0 .. 31);

   --  The request body: 36 fixed bytes, one or two dialects and padding to
   --  40, the preauth integrity context (46 bytes) and 2 bytes of padding,
   --  then the encryption context (14 bytes).
   Request_Length : constant := 102;
   subtype Request_Bytes is SMB.Bytes (0 .. Request_Length - 1);

   type Cipher_Id is (No_Cipher, AES_128_CCM, AES_128_GCM);

   --  The body of a NEGOTIATE request that offers 3.1.1, and 2.1 too when
   --  Allow_21 is set. SecurityMode is 3 (signing enabled and required) and
   --  Capabilities is SMB2_GLOBAL_CAP_ENCRYPTION. The preauth integrity
   --  context offers SHA-512 with Salt, and the encryption context offers
   --  AES-128-GCM, then AES-128-CCM.
   function Request
     (Guid : Guid_Bytes; Salt : Salt_Bytes; Allow_21 : Boolean)
      return Request_Bytes;

   --  Checks the negotiate contexts of a NEGOTIATE response Packet (header
   --  included) that selected 3.1.1, and returns the cipher it chose.
   --  The connection must fail unless Status is Ok, which requires:
   --  * a first context at an 8-byte-aligned offset after the fixed body,
   --    and every context, each 8-byte aligned, inside the packet;
   --  * exactly one preauth integrity context, with one hash algorithm,
   --    SHA-512, and a salt that fits its data;
   --  * at most one encryption context, with one cipher that is 0 (none) or
   --    one we offered;
   --  * at most one compression, transport and RDMA context each, and no
   --    signing context, which we never offer.
   --  Other context types are ignored. Without an encryption context, or
   --  with cipher 0, Cipher is No_Cipher.
   procedure Check_Response_Contexts
     (Packet : SMB.Bytes;
      Cipher : out Cipher_Id;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post => (if Status /= SMB.Ok then Cipher = No_Cipher);

end SMB.Core_Negotiate;
