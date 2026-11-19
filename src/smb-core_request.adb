package body SMB.Core_Request
  with SPARK_Mode
is
   procedure Prepare_Header
     (Packet : in out SMB.Bytes;
      Expected : SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status) is
      Field_Status : SMB.Core_Status;
      --  The header Initialize_Header writes, before the Flags.
      Unsigned : constant SMB.Spec.SMB2.Sync_Header :=
        SMB.Spec.SMB2.Request_Header
          (Command => SMB.Word (Expected.Command),
           Credit_Charge => Expected.Credit_Charge,
           Credit_Request => Expected.Credit_Request,
           Flags => 0,
           Message_Id => Expected.Message_Id,
           Tree_Id => Expected.Tree_Id,
           Session_Id => Expected.Session_Id)
      with Ghost;
   begin
      if Packet'Length < Header_Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id,
         Expected.Tree_Id, Expected.Session_Id, Expected.Credit_Request,
         Field_Status, Charge => Expected.Credit_Charge);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      pragma Assert (SMB.Spec.SMB2.Is_Sync_Header (Packet, Unsigned));
      if Expected.Request_Signed then
         SMB.Core_Wire.Write_U32 (Packet, 16, 8, Field_Status);
         if Field_Status /= SMB.Ok then
            Status := Field_Status;
            return;
         end if;
         --  Only the Flags changed.
         pragma Assert
           (SMB.Spec.SMB2.Is_Sync_Header
              (Packet,
               (Unsigned with delta Flags => SMB.Spec.SMB2.Flags_Signed)));
      end if;
      Status := SMB.Ok;
   end Prepare_Header;

   procedure Sign_Packet
     (Packet : in out SMB.Bytes;
      Used : Natural;
      Key : SMB.Bytes;
      Signing : SMB.Core_Negotiate.Signing_Id;
      SMB3_Key : SMB.AES.Key_128;
      Status : out SMB.Core_Status) is
   begin
      case Signing is
         when SMB.Core_Negotiate.HMAC_SHA256 =>
            SMB.Core_Wire.Sign
              (Packet
                 (Packet'First .. Packet'First + (Used - 1)), Key, Status);
         when SMB.Core_Negotiate.AES_CMAC | SMB.Core_Negotiate.AES_GMAC =>
            SMB.Core_Wire.Sign_SMB3
              (Packet
                 (Packet'First .. Packet'First + (Used - 1)), SMB3_Key,
               Signing, Status);
      end case;
   end Sign_Packet;
end SMB.Core_Request;
