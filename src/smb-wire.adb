with SMB.Core_Wire;

package body SMB.Wire is
   pragma SPARK_Mode (Off);

   use type SMB.DWord;
   use type SMB.QWord;

   procedure Check (Status : SMB.Core_Status) is
   begin
      if Status /= SMB.Ok then
         raise SMB.Protocol_Error with
           "invalid SMB wire value: " & SMB.Core_Status'Image (Status);
      end if;
   end Check;

   function U16 (Data : SMB.Bytes; Offset : Natural) return SMB.Word is
      Value : SMB.Word;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Read_U16 (Data, Offset, Value, Status);
      Check (Status);
      return Value;
   end U16;

   function U32 (Data : SMB.Bytes; Offset : Natural) return SMB.DWord is
      Value : SMB.DWord;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Read_U32 (Data, Offset, Value, Status);
      Check (Status);
      return Value;
   end U32;

   function U64 (Data : SMB.Bytes; Offset : Natural) return SMB.QWord is
      Value : SMB.QWord;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Read_U64 (Data, Offset, Value, Status);
      Check (Status);
      return Value;
   end U64;

   procedure Put_U16
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.Word) is
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Write_U16 (Data, Offset, Value, Status);
      Check (Status);
   end Put_U16;

   procedure Put_U32
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.DWord) is
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Write_U32 (Data, Offset, Value, Status);
      Check (Status);
   end Put_U32;

   procedure Put_U64
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.QWord) is
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Write_U64 (Data, Offset, Value, Status);
      Check (Status);
   end Put_U64;

   procedure Initialize_Header
     (Data : in out SMB.Bytes;
      Command : Command_Code;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord := 0;
      Session_Id : SMB.QWord := 0;
      Credit : SMB.Word := 1) is
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Initialize_Header
        (Data, SMB.Core_Wire.Command_Code (Command), Message_Id,
         Tree_Id, Session_Id, Credit, Status);
      Check (Status);
   end Initialize_Header;

   function Validate_Header
     (Data : SMB.Bytes; Expected : Expected_Header) return SMB.DWord is
      Nt_Status : SMB.DWord;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Validate_Header
        (Data,
         (Command => SMB.Core_Wire.Command_Code (Expected.Command),
          Message_Id => Expected.Message_Id,
          Tree_Id => Expected.Tree_Id,
          Session_Id => Expected.Session_Id,
          Match_Tree => Expected.Tree_Id /= 0,
          Match_Session => Expected.Session_Id /= 0,
          Signed => Expected.Signed),
         Nt_Status, Status);
      Check (Status);
      return Nt_Status;
   end Validate_Header;

   procedure Sign (Data : in out SMB.Bytes; Key : SMB.Bytes) is
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Sign (Data, Key, Status);
      Check (Status);
   end Sign;

   function Verify_Signature (Data : SMB.Bytes; Key : SMB.Bytes) return Boolean is
      Valid : Boolean;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Verify_Signature (Data, Key, Valid, Status);
      return Status = SMB.Ok and then Valid;
   end Verify_Signature;
end SMB.Wire;
