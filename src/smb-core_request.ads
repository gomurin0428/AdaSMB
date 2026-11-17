with SMB.AES;
with SMB.Core_Negotiate;
with SMB.Core_Wire;
with SMB.Engine;

--  The two steps that finish a request whose body is in place: writing its
--  header from the engine's expectation, and signing it. SMB.Core_Query and
--  SMB.Core_Resize share them; SMB.Core_Client and SMB.Core_Connection keep
--  copies of their own.
package SMB.Core_Request
  with SPARK_Mode
is
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Byte;

   Header_Length : constant Natural := SMB.Core_Wire.Header_Size;

   procedure Prepare_Header
     (Packet : in out SMB.Bytes;
      Expected : SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Packet'Length >= Header_Length then Status = SMB.Ok)
       and then (if Status = SMB.Ok then
          SMB.Core_Wire.Encoded_U16 (Packet, 4) =
            SMB.Word (Header_Length)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 6) = 1
          and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
            SMB.Word (Expected.Command)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 14) = 1
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
            (if Expected.Request_Signed then 8 else 0)
          and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
            Expected.Message_Id
          and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
            Expected.Tree_Id
          and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
            Expected.Session_Id
          and then
            (for all Index in Packet'Range =>
               (if Index - Packet'First >= Header_Length then
                  Packet (Index) = Packet'Old (Index))));

   --  Signs the first Used bytes of Packet with HMAC-SHA256 and Key for
   --  SMB 2.1, and with AES-128-CMAC or AES-128-GMAC, as Signing says, and
   --  SMB3_Key for 3.1.1. Only the signature field changes.
   procedure Sign_Packet
     (Packet : in out SMB.Bytes;
      Used : Natural;
      Key : SMB.Bytes;
      Signing : SMB.Core_Negotiate.Signing_Id;
      SMB3_Key : SMB.AES.Key_128;
      Status : out SMB.Core_Status)
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size
     and then Key'Length > 0
     and then Key'Length <= SMB.Maximum_Frame_Size
     and then Used <= Packet'Length
     and then Used >= Header_Length,
     Post =>
       Status = SMB.Ok
       and then
         (for all Index in Packet'Range =>
            (if Index < Packet'First + 48
               or else Index > Packet'First + 63
             then Packet (Index) = Packet'Old (Index)))
       and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
         SMB.Core_Wire.Encoded_U16 (Packet'Old, 4)
       and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
         SMB.Core_Wire.Encoded_U16 (Packet'Old, 12)
       and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
         SMB.Core_Wire.Encoded_U32 (Packet'Old, 16)
       and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
         SMB.Core_Wire.Encoded_U64 (Packet'Old, 24)
       and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
         SMB.Core_Wire.Encoded_U32 (Packet'Old, 36)
       and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
         SMB.Core_Wire.Encoded_U64 (Packet'Old, 40);
end SMB.Core_Request;
