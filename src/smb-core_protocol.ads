with SMB.Core_Wire;
with SMB.Spec.SMB2;

package SMB.Core_Protocol is
   pragma SPARK_Mode (On);
   use type SMB.Core_Wire.Command_Code;
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;

   --  One credit's worth (MS-SMB2 3.1.5.2): the most a request may carry
   --  without multi-credit, and so every request but a READ or WRITE here.
   Maximum_IO_Chunk : constant := 65_536;
   --  A READ or WRITE may take up to this many credits when the server
   --  supports SMB2_GLOBAL_CAP_LARGE_MTU. The READ response and the WRITE
   --  request, with their header and a transform header, stay inside a
   --  1 MiB frame.
   Maximum_Credit_Charge : constant := 15;
   Maximum_Read_Chunk : constant := Maximum_Credit_Charge * Maximum_IO_Chunk;
   Maximum_Write_Chunk : constant := Maximum_Credit_Charge * Maximum_IO_Chunk;
   Large_MTU_Capability : constant := 16#04#;

   --  The credits a request that moves Amount bytes takes once multi-credit
   --  requests are on: one per 64 KiB started (MS-SMB2 3.2.4.1.5), and one
   --  for none.
   function Credit_Charge (Amount : Natural) return Positive is
     (if Amount = 0 then 1 else (Amount - 1) / Maximum_IO_Chunk + 1);
   Maximum_Name_Bytes : constant := 65_534;

   --  FILE_RENAME_INFORMATION_TYPE_2 (MS-FSCC 2.4.42.2) for a name of
   --  Name_Length bytes: 20 bytes of fields, the name, then Padding, whose
   --  "Length ... MUST be the number of bytes required to make the size of
   --  this structure at least 24"; a server "MUST fail the request with
   --  STATUS_INFO_LENGTH_MISMATCH" when it is shorter (MS-SMB2 3.3.5.21.1).
   function Rename_Information_Length (Name_Length : Natural) return Natural is
     (Natural'Max (24, 20 + Name_Length))
   with Pre => Name_Length <= Maximum_Name_Bytes;

   --  The SET_INFO body that carries it: 32 bytes of fields, then it.
   function Rename_Request_Length (Name_Length : Natural) return Natural is
     (32 + Rename_Information_Length (Name_Length))
   with Pre => Name_Length <= Maximum_Name_Bytes;
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
      --  A NEGOTIATE response's SMB2_GLOBAL_CAP_LARGE_MTU.
      Large_MTU : Boolean := False;
      --  The dialect a NEGOTIATE response selected: 2.1 or 3.1.1.
      Dialect : SMB.Word := 0;
      --  The server encrypts the session (SESSION_SETUP's SessionFlags is
      --  SMB2_SESSION_FLAG_ENCRYPT_DATA, the only nonzero SessionFlags
      --  accepted; guest and null fail) or the share (TREE_CONNECT's
      --  SMB2_SHAREFLAG_ENCRYPT_DATA). The engine accepts either only with
      --  a cipher. Tested, not stated in Parse_Response's postcondition.
      Encrypt_Data : Boolean := False;
   end record;

   --  The times here and in File_Information are FILETIMEs: 100-nanosecond
   --  intervals since 1601-01-01 UTC, as the server sends them.
   type Directory_Info is record
      Next_Cursor : Natural := 0;
      Name_Offset : Natural := 0;
      Name_Length : Natural := 0;
      Size : SMB.QWord := 0;
      Attributes : SMB.DWord := 0;
      Creation_Time : SMB.QWord := 0;
      Last_Access_Time : SMB.QWord := 0;
      Last_Write_Time : SMB.QWord := 0;
      Change_Time : SMB.QWord := 0;
   end record;

   --  FILE_NETWORK_OPEN_INFORMATION (MS-FSCC), which QUERY_INFO returns for
   --  FileNetworkOpenInformation (class 34).
   type File_Information is record
      Creation_Time : SMB.QWord := 0;
      Last_Access_Time : SMB.QWord := 0;
      Last_Write_Time : SMB.QWord := 0;
      Change_Time : SMB.QWord := 0;
      Allocation_Size : SMB.QWord := 0;
      End_Of_File : SMB.QWord := 0;
      Attributes : SMB.DWord := 0;
   end record;
   Network_Open_Information_Class : constant := 34;
   Network_Open_Information_Size : constant := 56;

   --  Every byte of Data from Used on is zero: what a builder leaves past
   --  the request it writes, and the whole buffer when it fails.
   --  Its body, as those of SMB.Spec.SMB2's requests, is hidden from the
   --  callers, which use the builders' other clauses; the builders unhide
   --  what they prove.
   function Zero_After (Data : SMB.Bytes; Used : Natural) return Boolean is
     (for all Index in Data'Range =>
        (if Index - Data'First >= Used then Data (Index) = 0))
   with Ghost,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   procedure Build_Negotiate
     (Guid : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Guid'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 38
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 36
            and then SMB.Core_Wire.Encoded_U16 (Output, 2) = 1
            and then SMB.Core_Wire.Encoded_U16 (Output, 4) = 3
            and then SMB.Core_Wire.Encoded_U16 (Output, 6) = 0
            and then SMB.Core_Wire.Encoded_U32 (Output, 8) = 0
            and then SMB.Core_Wire.Encoded_U64 (Output, 28) = 0
            and then SMB.Core_Wire.Encoded_U16
              (Output, 36) = SMB.SMB2_Dialect_0210
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 12 + Index) =
                   Guid (Guid'First + Index)));

   procedure Build_Session_Setup
     (Token : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Token'Length <= 65_535
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status =
         (if Output'Length >= 24 + Token'Length then SMB.Ok
          else SMB.Resource_Limit)
       and then Used = (if Status = SMB.Ok then 24 + Token'Length else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Session_Setup_Request
              (Output,
               SMB.Spec.SMB2.Client_Session_Setup (SMB.Word (Token'Length)),
               Token)
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 25
            and then Output (Output'First + 2) = 0
            and then Output (Output'First + 3) = 3
            and then SMB.Core_Wire.Encoded_U16 (Output, 12) = 88
            and then SMB.Core_Wire.Encoded_U16 (Output, 14) =
              SMB.Word (Token'Length)
            and then SMB.Core_Wire.Encoded_U64 (Output, 16) = 0
            and then
              (if Token'Length = 0 then True
               else
                 (for all Index in 0 .. Token'Length - 1 =>
                    Output (Output'First + 24 + Index) =
                      Token (Token'First + Index))));

   procedure Build_Tree_Connect
     (Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       --  An odd length (not UTF-16) comes before a short buffer.
       Status =
         (if Name'Length mod 2 /= 0 then SMB.Invalid_Length
          elsif Output'Length < 8 + Name'Length then SMB.Resource_Limit
          else SMB.Ok)
       and then Used = (if Status = SMB.Ok then 8 + Name'Length else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Tree_Connect_Request
              (Output,
               SMB.Spec.SMB2.Client_Tree_Connect (SMB.Word (Name'Length)),
               Name)
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 9
            and then SMB.Core_Wire.Encoded_U16 (Output, 2) = 0
            and then SMB.Core_Wire.Encoded_U16 (Output, 4) = 72
            and then SMB.Core_Wire.Encoded_U16 (Output, 6) =
              SMB.Word (Name'Length)
            and then
              (for all Index in 0 .. Name'Length - 1 =>
                 Output (Output'First + 8 + Index) =
                   Name (Name'First + Index)));

   procedure Build_Create
     (Name : SMB.Bytes;
      Access_Mask, Disposition : SMB.DWord;
      Directory : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size
     --  MS-SMB2 2.2.13: CreateDisposition "MUST contain one of" FILE_SUPERSEDE
     --  to FILE_OVERWRITE_IF (0 to 5), and with FILE_DIRECTORY_FILE "the
     --  CreateDisposition field MUST be set to FILE_CREATE, FILE_OPEN_IF, or
     --  FILE_OPEN".
     and then Disposition <= 5
     and then (if Directory then Disposition in 1 .. 3),
     Post =>
       --  An odd length (not UTF-16) comes before a short buffer.
       Status =
         (if Name'Length mod 2 /= 0 then SMB.Invalid_Length
          elsif Output'Length < 56 + Natural'Max (1, Name'Length)
          then SMB.Resource_Limit
          else SMB.Ok)
       and then
         Used =
           (if Status = SMB.Ok then 56 + Natural'Max (1, Name'Length)
            else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Create_Request
              (Output,
               SMB.Spec.SMB2.Client_Create
                 (Desired_Access => Access_Mask,
                  Disposition => Disposition,
                  Directory => Directory,
                  Name_Length => SMB.Word (Name'Length)),
               Name)
            --  An empty name leaves the one byte of Buffer zero.
            and then (if Name'Length = 0 then Output (Output'First + 56) = 0)
            and then Used = 56 + Natural'Max (1, Name'Length)
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
     and then Amount <= Maximum_Read_Chunk
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status =
         (if Output'Length >= SMB.Spec.SMB2.Read_Request_Size then SMB.Ok
          else SMB.Resource_Limit)
       and then
         Used = (if Status = SMB.Ok then SMB.Spec.SMB2.Read_Request_Size else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Read_Request
              (Output,
               SMB.Spec.SMB2.Client_Read
                 (File_Id => File_Id,
                  Offset => Offset,
                  Length => SMB.DWord (Amount)))
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
     and then Data'Length <= Maximum_Write_Chunk
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status =
         (if Output'Length >= SMB.Spec.SMB2.Write_Fields_Size + Data'Length
          then SMB.Ok else SMB.Resource_Limit)
       and then
         Used =
           (if Status = SMB.Ok
            then SMB.Spec.SMB2.Write_Fields_Size + Data'Length else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Write_Request
              (Output,
               SMB.Spec.SMB2.Client_Write
                 (File_Id => File_Id,
                  Offset => Offset,
                  Length => SMB.DWord (Data'Length)),
               Data)
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
       Status =
         (if Output'Length >= SMB.Spec.SMB2.Close_Request_Size then SMB.Ok
          else SMB.Resource_Limit)
       and then
         Used =
           (if Status = SMB.Ok then SMB.Spec.SMB2.Close_Request_Size else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Close_Request
              (Output, (Flags => 0, File_Id => File_Id))
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
     Post =>
       Status = (if Output'Length >= 34 then SMB.Ok else SMB.Resource_Limit)
       and then Used = (if Status = SMB.Ok then 34 else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Query_Directory_Request
              (Output,
               SMB.Spec.SMB2.Client_Query_Directory (File_Id, Restart),
               SMB.Spec.SMB2.Every_Name)
            and then Used = 34
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 37
            and then Output (Output'First + 3) =
              (if Restart then 1 else 0)
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) = 0
            and then Output (Output'First + 8 .. Output'First + 23) =
              File_Id
            and then SMB.Core_Wire.Encoded_U16 (Output, 24) = 96
            and then SMB.Core_Wire.Encoded_U16 (Output, 26) = 2
            and then SMB.Core_Wire.Encoded_U32 (Output, 28) =
              SMB.DWord (Maximum_IO_Chunk)
            and then Output (Output'First + 32) = 16#2A#
            and then Output (Output'First + 33) = 0);

   procedure Build_Disposition
     (File_Id : SMB.Bytes;
      Delete_File : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 33
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 1
            and then Output (Output'First + 3) = 13
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) = 1
            and then SMB.Core_Wire.Encoded_U16 (Output, 8) = 96
            and then
              (for all Index in 10 .. 15 =>
                 Output (Output'First + Index) = 0)
            and then Output (Output'First + 10 .. Output'First + 15) =
              SMB.Bytes'(10 .. 15 => 0)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 16 + Index) =
                   File_Id (File_Id'First + Index))
            and then Output (Output'First + 32) =
              (if Delete_File then 1 else 0));

   --  A QUERY_INFO request body (MS-SMB2 2.2.37) for FileNetworkOpenInformation
   --  of the open File_Id, with room for exactly that structure: 40 bytes and
   --  the one-byte buffer that StructureSize 41 counts, left zero.
   procedure Build_Query_Information
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
            Used = 41
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 41
            and then Output (Output'First + 2) = 1
            and then Output (Output'First + 3) =
              Network_Open_Information_Class
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) =
              Network_Open_Information_Size
            and then
              (for all Index in 8 .. 23 =>
                 Output (Output'First + Index) = 0)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 24 + Index) =
                   File_Id (File_Id'First + Index))
            and then Output (Output'First + 40) = 0);

   --  The FILE_NETWORK_OPEN_INFORMATION at Offset in Buffer.
   function Network_Open_Information
     (Buffer : SMB.Bytes;
      Offset : Natural) return File_Information is
     ((Creation_Time => SMB.Core_Wire.Encoded_U64 (Buffer, Offset),
       Last_Access_Time => SMB.Core_Wire.Encoded_U64 (Buffer, Offset + 8),
       Last_Write_Time => SMB.Core_Wire.Encoded_U64 (Buffer, Offset + 16),
       Change_Time => SMB.Core_Wire.Encoded_U64 (Buffer, Offset + 24),
       Allocation_Size => SMB.Core_Wire.Encoded_U64 (Buffer, Offset + 32),
       End_Of_File => SMB.Core_Wire.Encoded_U64 (Buffer, Offset + 40),
       Attributes => SMB.Core_Wire.Encoded_U32 (Buffer, Offset + 48)))
   with Pre => Buffer'Length <= SMB.Maximum_Frame_Size
     and then Offset <= Buffer'Length
     and then Buffer'Length - Offset >= Network_Open_Information_Size;

   --  A SET_INFO request body (MS-SMB2 2.2.39) for FileEndOfFileInformation
   --  (class 20) of the open File_Id: the eight-byte EndOfFile, Size.
   End_Of_File_Information_Class : constant := 20;
   procedure Build_End_Of_File
     (File_Id : SMB.Bytes;
      Size : SMB.QWord;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 40
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 1
            and then Output (Output'First + 3) =
              End_Of_File_Information_Class
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) = 8
            and then SMB.Core_Wire.Encoded_U16 (Output, 8) = 96
            and then
              (for all Index in 10 .. 15 =>
                 Output (Output'First + Index) = 0)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 16 + Index) =
                   File_Id (File_Id'First + Index))
            and then SMB.Core_Wire.Encoded_U64 (Output, 32) = Size);

   procedure Build_Rename
     (File_Id : SMB.Bytes;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = Rename_Request_Length (Name'Length)
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 1
            and then Output (Output'First + 3) = 10
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) =
              SMB.DWord (Rename_Information_Length (Name'Length))
            and then SMB.Core_Wire.Encoded_U16 (Output, 8) = 96
            and then
              (for all Index in 10 .. 15 =>
                 Output (Output'First + Index) = 0)
            and then Output (Output'First + 10 .. Output'First + 15) =
              SMB.Bytes'(10 .. 15 => 0)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 16 + Index) =
                   File_Id (File_Id'First + Index))
            and then
              (for all Index in 32 .. 47 =>
                 Output (Output'First + Index) = 0)
            and then Output (Output'First + 32 .. Output'First + 47) =
              SMB.Bytes'(32 .. 47 => 0)
            and then SMB.Core_Wire.Encoded_U32 (Output, 48) =
              SMB.DWord (Name'Length)
            and then
              (if Name'Length > 0 then
                 Output
                   (Output'First + 52 .. Output'First + 51 + Name'Length) =
                   Name)
            and then
              (Name'Length = 0
               or else
                 (for all Index in 0 .. Name'Length - 1 =>
                    Output (Output'First + 52 + Index) =
                      Name (Name'First + Index)))
            and then
              (for all Index in 52 + Name'Length .. Used - 1 =>
                 Output (Output'First + Index) = 0));

   procedure Build_Simple
     (Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status = (if Output'Length >= 4 then SMB.Ok else SMB.Resource_Limit)
       and then Used = (if Status = SMB.Ok then 4 else 0)
       and then Zero_After (Output, Used)
       and then
         (if Status = SMB.Ok then
            SMB.Spec.SMB2.Is_Logoff_Request (Output)
            and then SMB.Spec.SMB2.Is_Tree_Disconnect_Request (Output)
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 4
            and then SMB.Core_Wire.Encoded_U16 (Output, 2) = 0);

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
         (if Command = 0 and then Nt_Status = SMB.Success then
            Packet'Length >= 128
            and then Info.Large_MTU =
              ((SMB.Core_Wire.Encoded_U32 (Packet, 88)
                  and Large_MTU_Capability) /= 0)
            and then Info.Max_Read in 1 .. Maximum_Read_Chunk
            and then (Info.Large_MTU or else Info.Max_Read <= Maximum_IO_Chunk)
            and then Info.Max_Write in 1 .. Maximum_Write_Chunk
            and then
              (Info.Large_MTU or else Info.Max_Write <= Maximum_IO_Chunk)
            and then Info.Max_Read = Natural (SMB.DWord'Min
              ((if Info.Large_MTU then Maximum_Read_Chunk
                else Maximum_IO_Chunk),
               SMB.Core_Wire.Encoded_U32 (Packet, 96)))
            and then Info.Max_Write = Natural (SMB.DWord'Min
              ((if Info.Large_MTU then Maximum_Write_Chunk
                else Maximum_IO_Chunk),
               SMB.Core_Wire.Encoded_U32 (Packet, 100)))
          elsif Command = 3 and then Nt_Status = SMB.Success then
            Packet'Length >= 80
            and then Info.Tree_Id /= 0
            and then Info.Tree_Id = SMB.Core_Wire.Encoded_U32 (Packet, 36))
       and then
         (if Command = 8 and then Nt_Status = SMB.Success then
            Packet'Length >= 80
            and then Natural (Packet (Packet'First + 66)) =
              Info.Data_Offset
            and then Info.Data_Length <= Maximum_Read_Chunk
            and then Info.Data_Length = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68))
          elsif Command = 9
            and then Nt_Status = SMB.Success
          then Packet'Length >= 80
            and then Info.Count <= Maximum_Write_Chunk
            and then Info.Count = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68))
          elsif (Command = 14 or else Command = 16)
            and then Nt_Status = SMB.Success
          then Packet'Length >= 72
            and then Info.Data_Offset = Natural
              (SMB.Core_Wire.Encoded_U16 (Packet, 66))
            and then
              (Info.Data_Length = 0 or else Info.Data_Offset >= 72)
            and then Info.Data_Length <= Maximum_IO_Chunk
            and then Info.Data_Length = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68)))),
     Contract_Cases =>
       (Command = 0 and then Nt_Status = SMB.Success =>
          (if Status = SMB.Ok then
             Packet'Length >= 128
             and then Info.Dialect = SMB.Core_Wire.Encoded_U16 (Packet, 68)
             and then Info.Dialect in SMB.SMB2_Dialect_0210
                                    | SMB.SMB2_Dialect_0311
             and then Info.Data_Length =
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 122))
             and then
               (if Info.Data_Length = 0 then Info.Data_Offset = 0
                else Info.Data_Offset >= 128
                  and then Info.Data_Offset =
                    Natural (SMB.Core_Wire.Encoded_U16 (Packet, 120)))
           else True),
        (Command = 1 and then
           (Nt_Status = SMB.Success or else
              Nt_Status = SMB.Status_More_Processing_Required)) =>
          (if Status = SMB.Ok then
             Packet'Length >= 72
             and then Info.Session_Id /= 0
             and then Info.Session_Id =
               SMB.Core_Wire.Encoded_U64 (Packet, 40)
             and then (Info.Data_Length = 0 or else Info.Data_Offset >= 72)
             and then Info.Data_Offset =
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 68))
             and then Info.Data_Length =
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 70))
           else True),
        others => True);

   procedure Parse_Directory_Entry
     (Buffer : SMB.Bytes;
      Cursor : in out Natural;
      Info : out Directory_Info;
      Status : out SMB.Core_Status)
   with Pre => Buffer'Length <= SMB.Maximum_Frame_Size
     and then Cursor <= Buffer'Length,
     Post => Cursor <= Buffer'Length
       and then (if Status /= SMB.Ok then Cursor = Cursor'Old)
       and then (if Status = SMB.Ok then
         Cursor > Cursor'Old
         and then Buffer'Length - Cursor'Old >= 104
         and then
           ((Cursor = Buffer'Length) =
             (SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old) = 0))
         and then
           (if Cursor < Buffer'Length then
              SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old) <
                SMB.DWord (Buffer'Length - Cursor'Old)
              and then Cursor - Cursor'Old =
                Natural (SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old)))
         and then Info.Next_Cursor = Cursor
         and then Info.Name_Length > 0
         and then Info.Name_Offset <= Buffer'Length
         and then Info.Name_Length <= Buffer'Length - Info.Name_Offset
         and then Info.Name_Offset = Cursor'Old + 104
         and then Info.Name_Length = Natural
           (SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old + 60))
         and then Info.Size =
           SMB.Core_Wire.Encoded_U64 (Buffer, Cursor'Old + 40)
         and then Info.Attributes = SMB.Core_Wire.Encoded_U32
           (Buffer, Cursor'Old + 56)
         and then Info.Creation_Time =
           SMB.Core_Wire.Encoded_U64 (Buffer, Cursor'Old + 8)
         and then Info.Last_Access_Time =
           SMB.Core_Wire.Encoded_U64 (Buffer, Cursor'Old + 16)
         and then Info.Last_Write_Time =
           SMB.Core_Wire.Encoded_U64 (Buffer, Cursor'Old + 24)
         and then Info.Change_Time =
           SMB.Core_Wire.Encoded_U64 (Buffer, Cursor'Old + 32));

   procedure Advance_Transfer
     (Position : in out SMB.QWord;
      Remaining : in out Natural;
      Requested, Count : Natural;
      Status : out SMB.Core_Status;
      Require_Progress : Boolean := True)
   with Pre => Requested <= Maximum_Read_Chunk
     and then Count <= Maximum_Read_Chunk
     and then Remaining <= SMB.Maximum_Frame_Size,
     Post => Status =
       (if (Count = 0 and then Requested /= 0 and then Require_Progress)
          or else Count > Requested or else Count > Remaining'Old
        then SMB.Invalid_Value
        elsif SMB.QWord (Count) > SMB.QWord'Last - Position'Old
        then SMB.Invalid_Offset
        else SMB.Ok)
       and then Remaining <= Remaining'Old
       and then (if Status = SMB.Ok then
          Count <= Requested
          and then SMB.QWord (Count) <= SMB.QWord'Last - Position'Old
          and then Remaining = Remaining'Old - Count
          and then Position = Position'Old + SMB.QWord (Count)
        else Position = Position'Old
          and then Remaining = Remaining'Old);

   procedure Select_Transfer_Amount
     (Remaining, Limit : Natural;
      Amount : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Remaining <= SMB.Maximum_Frame_Size
     and then Limit <= Maximum_Read_Chunk,
     Post => Status =
       (if Remaining /= 0 and then Limit = 0 then SMB.Invalid_Value
        else SMB.Ok)
       and then Amount <= Remaining
       and then Amount <= Limit
       and then (if Status = SMB.Ok
         then Amount = Natural'Min (Remaining, Limit)
         else Amount = 0);

   procedure Check_Transfer_Range
     (Base_Offset : SMB.QWord;
      Total : Natural;
      Status : out SMB.Core_Status)
   with Pre => Total <= SMB.Maximum_Frame_Size,
     Post => Status =
       (if SMB.QWord (Total) > SMB.QWord'Last - Base_Offset
        then SMB.Invalid_Offset
        else SMB.Ok);

   procedure Count_Directory_Page
     (Pages : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Pages <= Maximum_Directory_Pages,
     Post => Status =
       (if Pages'Old = Maximum_Directory_Pages then SMB.Resource_Limit
        else SMB.Ok)
       and then Pages <= Maximum_Directory_Pages
       and then (if Status = SMB.Ok then Pages = Pages'Old + 1
         else Pages = Pages'Old);

   procedure Count_Directory_Entry
     (Entries : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Entries <= Maximum_Directory_Entries,
     Post => Status =
       (if Entries'Old = Maximum_Directory_Entries then SMB.Resource_Limit
        else SMB.Ok)
       and then Entries <= Maximum_Directory_Entries
       and then (if Status = SMB.Ok then Entries = Entries'Old + 1
         else Entries = Entries'Old);
end SMB.Core_Protocol;
