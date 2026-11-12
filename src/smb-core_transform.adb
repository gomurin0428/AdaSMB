with SMB.AES.CCM;
with SMB.AES.GCM;

package body SMB.Core_Transform is
   pragma SPARK_Mode (On);

   subtype Header_Bytes is SMB.Bytes (0 .. Header_Size - 1);
   subtype Tag_Bytes is SMB.Bytes (0 .. 15);

   --  The associated data: the header from the Nonce field on.
   subtype AAD_Range is Natural range 20 .. Header_Size - 1;

   procedure Encrypt
     (Cipher : AEAD_Cipher;
      Key : SMB.Bytes;
      Nonce : Nonce_Field;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : out Tag_Bytes)
   with Pre => Fits_Key (Cipher, Key)
     and then AAD'Length = 32 and then Data'Length <= SMB.Maximum_Frame_Size
   is
   begin
      case Cipher is
         when SMB.Core_Negotiate.AES_128_CCM
            | SMB.Core_Negotiate.AES_256_CCM =>
            SMB.AES.CCM.Seal (Key, Nonce (0 .. 10), AAD, Data, Tag);
         when SMB.Core_Negotiate.AES_128_GCM
            | SMB.Core_Negotiate.AES_256_GCM =>
            SMB.AES.GCM.Seal (Key, Nonce (0 .. 11), AAD, Data, Tag);
      end case;
   end Encrypt;

   procedure Decrypt
     (Cipher : AEAD_Cipher;
      Key : SMB.Bytes;
      Nonce : Nonce_Field;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : Tag_Bytes;
      Authentic : out Boolean)
   with
     Pre => Fits_Key (Cipher, Key)
       and then AAD'Length = 32 and then Data'Length <= SMB.Maximum_Frame_Size,
     Post => (if not Authentic then (for all Value of Data => Value = 0))
   is
   begin
      case Cipher is
         when SMB.Core_Negotiate.AES_128_CCM
            | SMB.Core_Negotiate.AES_256_CCM =>
            SMB.AES.CCM.Open
              (Key, Nonce (0 .. 10), AAD, Data, Tag, Authentic);
         when SMB.Core_Negotiate.AES_128_GCM
            | SMB.Core_Negotiate.AES_256_GCM =>
            SMB.AES.GCM.Open
              (Key, Nonce (0 .. 11), AAD, Data, Tag, Authentic);
      end case;
   end Decrypt;

   procedure Seal
     (Cipher : AEAD_Cipher;
      Key : SMB.Bytes;
      Nonce : Nonce_Field;
      Session_Id : SMB.QWord;
      Message : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   is
      Header : Header_Bytes := (others => 0);
      Used_Nonce : Nonce_Field := (others => 0);
      Tag : Tag_Bytes;
      Write_Status : SMB.Core_Status;
      Last : Natural;
   begin
      Output := (others => 0);
      Used := 0;
      if Output'Length < Header_Size + Message'Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Last := Output'First + (Header_Size + Message'Length - 1);
      for Index in 0 .. Nonce_Length (Cipher) - 1 loop
         Used_Nonce (Index) := Nonce (Index);
         pragma Loop_Invariant
           (for all Earlier in Nonce_Field'Range =>
              Used_Nonce (Earlier) =
                (if Earlier <= Index then Nonce (Earlier) else 0));
      end loop;
      Header (0 .. 3) := (16#FD#, 16#53#, 16#4D#, 16#42#);
      Header (20 .. 35) := Used_Nonce;
      SMB.Core_Wire.Write_U32
        (Header, 36, SMB.DWord (Message'Length), Write_Status);
      pragma Assert (Write_Status = SMB.Ok);
      SMB.Core_Wire.Write_U16 (Header, 42, 1, Write_Status);
      pragma Assert (Write_Status = SMB.Ok);
      SMB.Core_Wire.Write_U64 (Header, 44, Session_Id, Write_Status);
      pragma Assert (Write_Status = SMB.Ok);
      Output (Output'First + Header_Size .. Last) := Message;
      Encrypt
        (Cipher, Key, Used_Nonce, Header (AAD_Range),
         Output (Output'First + Header_Size .. Last), Tag);
      Header (4 .. 19) := Tag;
      Output (Output'First .. Output'First + (Header_Size - 1)) := Header;
      Used := Header_Size + Message'Length;
      Status := SMB.Ok;
   end Seal;

   procedure Unwrap
     (Cipher : AEAD_Cipher;
      Key : SMB.Bytes;
      Session_Id : SMB.QWord;
      Packet : in out SMB.Bytes;
      Status : out SMB.Core_Status)
   is
      Header : Header_Bytes;
      Authentic : Boolean;
   begin
      if Packet'Length <= Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Header := Packet (Packet'First .. Packet'First + (Header_Size - 1));
      if not Is_Transformed (Header)
        or else SMB.Core_Wire.Encoded_U16 (Header, 42) /= 1
      then
         Status := SMB.Invalid_Protocol;
      elsif SMB.Core_Wire.Encoded_U32 (Header, 36) /=
        SMB.DWord (Packet'Length - Header_Size)
      then
         Status := SMB.Invalid_Length;
      elsif SMB.Core_Wire.Encoded_U64 (Header, 44) /= Session_Id then
         Status := SMB.Correlation_Error;
      else
         Decrypt
           (Cipher, Key, Header (20 .. 35), Header (AAD_Range),
            Packet (Packet'First + Header_Size .. Packet'Last),
            Header (4 .. 19), Authentic);
         if not Authentic then
            Status := SMB.Signature_Error;
         elsif Packet'Length - Header_Size < SMB2_Header_Size then
            Status := SMB.Invalid_Length;
         elsif Packet (Packet'First + Header_Size) /= 16#FE#
           or else Packet (Packet'First + Header_Size + 1) /= 16#53#
           or else Packet (Packet'First + Header_Size + 2) /= 16#4D#
           or else Packet (Packet'First + Header_Size + 3) /= 16#42#
         then
            Status := SMB.Invalid_Protocol;
         elsif SMB.Core_Wire.Encoded_U64 (Packet, Header_Size + 40) /=
           Session_Id
         then
            Status := SMB.Correlation_Error;
         else
            Status := SMB.Ok;
            return;
         end if;
      end if;
      Packet (Packet'First + Header_Size .. Packet'Last) := (others => 0);
   end Unwrap;

end SMB.Core_Transform;
