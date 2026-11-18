package body SMB.Core_Request
  with SPARK_Mode
is
   procedure Prepare_Header
     (Packet : in out SMB.Bytes;
      Expected : SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status) is
      Field_Status : SMB.Core_Status;
   begin
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: every caller checks the output length first
      if Packet'Length < Header_Length then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id,
         Expected.Tree_Id, Expected.Session_Id, Expected.Credit_Request,
         Field_Status, Charge => Expected.Credit_Charge);
      --  adamutant:disable-next-line ConditionalExpression: a header fits the packet, so the write succeeds
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Field_Status;
         return;
      end if;
      --  adamutant:disable-next-line ConditionalExpression: every request built here is signed
      if Expected.Request_Signed then
         SMB.Core_Wire.Write_U32 (Packet, 16, 8, Field_Status);
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: a header fits the packet, so the write succeeds
         if Field_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := Field_Status;
            return;
         end if;
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
