with SMB.Core_Wire;

package SMB.Core_Protocol is
   pragma SPARK_Mode (On);
   use type SMB.Core_Wire.Command_Code;
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;

   Maximum_IO_Chunk : constant := 65_536;
   Maximum_Name_Bytes : constant := 65_534;
   Maximum_Directory_Entries : constant := 100_000;
   Maximum_Directory_Pages : constant := 4_096;

   type Response_Info is record
      Data_Offset : Natural := 0;
      Data_Length : Natural := 0;
      Max_Read : Natural := 0;
      Max_Write : Natural := 0;
      Session_Id : SMB.QWord := 0;
      Tree_Id : SMB.DWord := 0;
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Count : Natural := 0;
   end record;

   type Directory_Info is record
      Next_Cursor : Natural := 0;
      Name_Offset : Natural := 0;
      Name_Length : Natural := 0;
      Size : SMB.QWord := 0;
      Attributes : SMB.DWord := 0;
   end record;

   procedure Build_Negotiate
     (Guid : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Guid'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Build_Session_Setup
     (Token : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Token'Length <= 65_535
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Build_Tree_Connect
     (Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Build_Create
     (Name : SMB.Bytes;
      Access_Mask, Disposition : SMB.DWord;
      Directory : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 56 + Natural'Max (1, Name'Length)
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 24 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte (Access_Mask, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 28 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte
                     ((if Directory then 16#10# else 0), Byte_Index))
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 40 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte
                     ((if Directory then 1 else 16#40#), Byte_Index))
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 36 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte (Disposition, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 1 =>
                 Output (Output'First + 46 + Byte_Index) =
                   SMB.Core_Wire.U16_Byte
                     (SMB.Word (Name'Length), Byte_Index)));

   procedure Build_Read
     (File_Id : SMB.Bytes;
      Offset : SMB.QWord;
      Amount : Natural;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Amount <= Maximum_IO_Chunk
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 49
            and then
              Output (Output'First + 4) =
                SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 0)
            and then Output (Output'First + 5) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 1)
            and then Output (Output'First + 6) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 2)
            and then Output (Output'First + 7) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 3)
            and then
              SMB.Core_Wire.Encoded_U64 (Output, 8) = Offset
            and then
              (for all Byte_Index in 0 .. 7 =>
                 Output (Output'First + 8 + Byte_Index) =
                   SMB.Core_Wire.U64_Byte (Offset, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 15 =>
                 Output (Output'First + 16 + Byte_Index) =
                   File_Id (File_Id'First + Byte_Index)));

   procedure Build_Write
     (File_Id : SMB.Bytes;
      Offset : SMB.QWord;
      Data : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Data'Length <= Maximum_IO_Chunk
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 48 + Data'Length
            and then
              Output (Output'First + 4) =
                SMB.Core_Wire.U32_Byte
                  (SMB.DWord (Data'Length), 0)
            and then Output (Output'First + 5) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 1)
            and then Output (Output'First + 6) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 2)
            and then Output (Output'First + 7) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 3)
            and then
              SMB.Core_Wire.Encoded_U64 (Output, 8) = Offset
            and then
              (for all Byte_Index in 0 .. 7 =>
                 Output (Output'First + 8 + Byte_Index) =
                   SMB.Core_Wire.U64_Byte (Offset, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 15 =>
                 Output (Output'First + 16 + Byte_Index) =
                   File_Id (File_Id'First + Byte_Index))
            and then
              (Data'Length = 0
               or else
                 (for all Byte_Index in 0 .. Data'Length - 1 =>
                    Output (Output'First + 48 + Byte_Index) =
                      Data (Data'First + Byte_Index))));

   procedure Build_Close
     (File_Id : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 24
            and then
              Output (Output'First + 8 .. Output'First + 23) = File_Id);

   procedure Build_Query_Directory
     (File_Id : SMB.Bytes;
      Restart : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Build_Disposition
     (File_Id : SMB.Bytes;
      Delete_File : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Build_Rename
     (File_Id : SMB.Bytes;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Build_Simple
     (Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Parse_Response
     (Packet : SMB.Bytes;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Info : out Response_Info;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post => (if Status = SMB.Ok then
       Info.Data_Offset <= Packet'Length
       and then Info.Data_Length <= Packet'Length - Info.Data_Offset
       and then
         (if Command = 8 and then Nt_Status = SMB.Success then
            Packet'Length >= 80
            and then Natural (Packet (Packet'First + 66)) =
              Info.Data_Offset
            and then Packet (Packet'First + 67) = 0
                and then Info.Data_Length <= Maximum_IO_Chunk
            and then Info.Data_Length = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68))
          elsif Command = 9
            and then Nt_Status = SMB.Success
          then Packet'Length >= 80
            and then Info.Count <= Maximum_IO_Chunk
            and then Info.Count = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68))));

   procedure Parse_Directory_Entry
     (Buffer : SMB.Bytes;
      Cursor : in out Natural;
      Info : out Directory_Info;
      Status : out SMB.Core_Status)
   with Pre => Buffer'Length <= SMB.Maximum_Frame_Size
     and then Cursor <= Buffer'Length,
     Post => Cursor <= Buffer'Length
       and then (if Status = SMB.Ok then
         Cursor > Cursor'Old
         and Info.Next_Cursor = Cursor
         and Info.Name_Offset <= Buffer'Length
         and Info.Name_Length <= Buffer'Length - Info.Name_Offset);

   procedure Advance_Transfer
     (Position : in out SMB.QWord;
      Remaining : in out Natural;
      Requested, Count : Natural;
      Status : out SMB.Core_Status;
      Require_Progress : Boolean := True)
   with Pre => Requested <= Maximum_IO_Chunk
     and then Count <= Maximum_IO_Chunk
     and then Remaining <= SMB.Maximum_Frame_Size,
     Post => Remaining <= Remaining'Old
       and then (if Status = SMB.Ok then
          Remaining = Remaining'Old - Count
          and then Position = Position'Old + SMB.QWord (Count)
        else Position = Position'Old
          and then Remaining = Remaining'Old);

   procedure Select_Transfer_Amount
     (Remaining, Limit : Natural;
      Amount : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Remaining <= SMB.Maximum_Frame_Size
     and then Limit <= Maximum_IO_Chunk,
     Post => Amount <= Remaining
       and then Amount <= Limit
       and then (if Status = SMB.Ok
         then Amount = Natural'Min (Remaining, Limit)
         else Amount = 0);

   procedure Check_Transfer_Range
     (Base_Offset : SMB.QWord;
      Total : Natural;
      Status : out SMB.Core_Status)
   with Pre => Total <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          SMB.QWord (Total) <= SMB.QWord'Last - Base_Offset);

   procedure Count_Directory_Page
     (Pages : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Pages <= Maximum_Directory_Pages,
     Post => Pages <= Maximum_Directory_Pages
       and then (if Status = SMB.Ok then Pages = Pages'Old + 1
         else Pages = Pages'Old);

   procedure Count_Directory_Entry
     (Entries : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Entries <= Maximum_Directory_Entries,
     Post => Entries <= Maximum_Directory_Entries
       and then (if Status = SMB.Ok then Entries = Entries'Old + 1
         else Entries = Entries'Old);
end SMB.Core_Protocol;
