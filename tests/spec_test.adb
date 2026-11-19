--  The specification packages (SMB.Spec.*) run on their own, on published
--  vectors and on properties that follow from the standards. GNATprove ties
--  the core's code to the specifications; this program ties the
--  specifications to the standards. It uses nothing from the implementation.
--
--  Ghost functions can be called only from ghost code and assertions, so each
--  check is a pragma Assert (checked: this program needs the assertion
--  policy Check), followed by Passed, which counts it.
pragma Assertion_Policy (Assert => Check, Ghost => Check);

with Ada.Text_IO;
with Interfaces;
with SMB;
with SMB.Spec.Encoding;
with SMB.Spec.SMB2;

procedure Spec_Test is
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Checks : Natural := 0;

   procedure Passed is
   begin
      Checks := Checks + 1;
   end Passed;

   --  MS-SMB2 and MS-DTYP: little-endian unsigned integers.
   procedure Test_Encoding is
      package E renames SMB.Spec.Encoding;
      --  The header of the WRITE request in Microsoft's "SMB 3.1.1
      --  Encryption in Windows 10" blog, appendix A.2 (the message
      --  test_suite decrypts): ProtocolId FE 'S' 'M' 'B', StructureSize 64,
      --  CreditCharge 1, Status 0, Command WRITE (9), CreditRequest 1, Flags
      --  SMB2_FLAGS_SIGNED, NextCommand 0, MessageId 5, Reserved 0xFEFF,
      --  TreeId 1, SessionId 0x0000100000000021, Signature 0.
      Header : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#09#, 16#00#, 16#01#, 16#00#,
         16#08#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#05#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#,
         16#21#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      Shifted : constant SMB.Bytes (100 .. 163) := Header;
      Values : constant array (Positive range <>) of SMB.QWord :=
        (0, 1, 16#FF#, 16#100#, 16#FFFF#, 16#1_0000#, 16#FFFF_FFFF#,
         16#1_0000_0000#, 16#0123_4567_89AB_CDEF#, 16#8000_0000_0000_0000#,
         SMB.QWord'Last);
      Encoded : SMB.Bytes (0 .. 7) with Ghost;

      procedure Encode (Value : SMB.QWord) with Ghost is
      begin
         for Index in Encoded'Range loop
            Encoded (Index) := E.LE_Byte (Value, Index);
         end loop;
      end Encode;
   begin
      pragma Assert (E.LE32 (Header, 0) = 16#424D_53FE#, "ProtocolId");
      Passed;
      pragma Assert (E.LE16 (Header, 4) = 64, "StructureSize");
      Passed;
      pragma Assert (E.LE16 (Header, 6) = 1, "CreditCharge");
      Passed;
      pragma Assert (E.LE32 (Header, 8) = 0, "Status");
      Passed;
      pragma Assert (E.LE16 (Header, 12) = 9, "Command");
      Passed;
      pragma Assert (E.LE16 (Header, 14) = 1, "CreditRequest");
      Passed;
      pragma Assert (E.LE32 (Header, 16) = 8, "Flags");
      Passed;
      pragma Assert (E.LE64 (Header, 24) = 5, "MessageId");
      Passed;
      pragma Assert (E.LE32 (Header, 32) = 16#FEFF#, "Reserved");
      Passed;
      pragma Assert (E.LE32 (Header, 36) = 1, "TreeId");
      Passed;
      pragma Assert
        (E.LE64 (Header, 40) = 16#0000_1000_0000_0021#, "SessionId");
      Passed;
      --  Offsets count from Data'First, whatever it is.
      pragma Assert
        (E.LE16 (Shifted, 4) = 64
         and then E.LE64 (Shifted, 40) = 16#0000_1000_0000_0021#,
         "offsets from Data'First");
      Passed;
      --  LE_Byte is the inverse of LE64, and shorter reads give the low bits.
      for Value of Values loop
         Encode (Value);
         pragma Assert (E.LE64 (Encoded, 0) = Value, "LE_Byte then LE64");
         Passed;
         pragma Assert
           (E.LE32 (Encoded, 0) = SMB.DWord (Value mod 2 ** 32)
            and then E.LE16 (Encoded, 0) = SMB.Word (Value mod 2 ** 16),
            "shorter reads are the low bits");
         Passed;
      end loop;
   end Test_Encoding;
   --  MS-SMB2 2.2.1.2: the SYNC header, on published messages: the WRITE
   --  request and READ response of Microsoft's "SMB 3.1.1 Encryption in
   --  Windows 10" blog (appendix A.2), and SESSION_SETUP messages of its
   --  appendix A.1, whose fields differ where those agree (CreditCharge
   --  and CreditRequest, Status, Flags, a Signature that is not zero); the
   --  same messages as test_suite's. Where no published message has a
   --  value (NextCommand), a published one is changed.
   procedure Test_SMB2_Header is
      package S renames SMB.Spec.SMB2;
      use type S.Sync_Header;
      Write_Request : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#09#, 16#00#, 16#01#, 16#00#,
         16#08#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#05#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#,
         16#21#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         --  The start of the WRITE request's body: StructureSize 49.
         16#31#, 16#00#);
      Read_Response : constant SMB.Bytes (1000 .. 1063) :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#08#, 16#00#, 16#01#, 16#00#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#06#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#,
         16#21#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      --  The first SESSION_SETUP request: CreditRequest 0x80.
      Setup_Request : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#01#, 16#00#, 16#80#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      --  The first SESSION_SETUP response: Status
      --  STATUS_MORE_PROCESSING_REQUIRED.
      Setup_Response_1 : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#16#, 16#00#, 16#00#, 16#C0#, 16#01#, 16#00#, 16#01#, 16#00#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#25#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      --  The final SESSION_SETUP response, signed: Flags
      --  SERVER_TO_REDIR | SIGNED and its Signature.
      Setup_Response_2 : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#01#, 16#00#, 16#80#, 16#00#,
         16#09#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#02#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#25#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#6B#, 16#85#, 16#A4#, 16#51#, 16#9A#, 16#0F#, 16#3E#, 16#EA#,
         16#35#, 16#BA#, 16#94#, 16#6D#, 16#D3#, 16#AF#, 16#E6#, 16#B8#);
      Setup_Request_Header : constant S.Sync_Header :=
        (Credit_Charge => 1, Status => 0, Command => S.Session_Setup,
         Credits => 16#80#, Flags => 0, Next_Command => 0, Message_Id => 1,
         Reserved => 16#FEFF#, Tree_Id => 0, Session_Id => 0,
         Signature => (others => 0))
      with Ghost;
      Setup_Response_1_Header : constant S.Sync_Header :=
        (Setup_Request_Header with delta
           Status => 16#C000_0016#, Credits => 1,
           Flags => S.Flags_Server_To_Redir,
           Session_Id => 16#0000_1000_0000_0025#)
      with Ghost;
      Setup_Response_2_Header : constant S.Sync_Header :=
        (Setup_Request_Header with delta
           Flags => S.Flags_Server_To_Redir + S.Flags_Signed,
           Message_Id => 2, Session_Id => 16#0000_1000_0000_0025#,
           Signature =>
             (16#6B#, 16#85#, 16#A4#, 16#51#, 16#9A#, 16#0F#, 16#3E#, 16#EA#,
              16#35#, 16#BA#, 16#94#, 16#6D#, 16#D3#, 16#AF#, 16#E6#, 16#B8#))
      with Ghost;
      Write_Header : constant S.Sync_Header :=
        (Credit_Charge => 1, Status => 0, Command => S.Write, Credits => 1,
         Flags => S.Flags_Signed, Next_Command => 0, Message_Id => 5,
         Reserved => 16#FEFF#, Tree_Id => 1,
         Session_Id => 16#0000_1000_0000_0021#, Signature => (others => 0))
      with Ghost;
      Read_Header : constant S.Sync_Header :=
        (Write_Header with delta
           Command => S.Read, Flags => S.Flags_Server_To_Redir,
           Message_Id => 6)
      with Ghost;
   begin
      pragma Assert (S.Is_Sync_Header (Write_Request, Write_Header),
                     "the WRITE request's header");
      Passed;
      pragma Assert (S.Is_Sync_Header (Read_Response, Read_Header),
                     "the READ response's header, at other bounds");
      Passed;
      pragma Assert
        (S.Is_Sync_Header (Setup_Request, Setup_Request_Header),
         "the first SESSION_SETUP request's header");
      Passed;
      pragma Assert
        (S.Is_Sync_Header (Setup_Response_1, Setup_Response_1_Header),
         "the first SESSION_SETUP response's header");
      Passed;
      pragma Assert
        (S.Is_Sync_Header (Setup_Response_2, Setup_Response_2_Header),
         "the signed SESSION_SETUP response's header");
      Passed;
      --  NextCommand, which no published message here sets: the WRITE
      --  request as the first of a compound whose next request is 0x70
      --  bytes on.
      declare
         Compounded : SMB.Bytes := Write_Request;
      begin
         Compounded (Compounded'First + 20) := 16#70#;
         pragma Assert
           (S.Is_Sync_Header
              (Compounded, (Write_Header with delta Next_Command => 16#70#))
            and then not S.Is_Sync_Header (Compounded, Write_Header),
            "NextCommand");
         Passed;
      end;
      --  ProtocolId and StructureSize are part of the header.
      declare
         Changed : SMB.Bytes := Write_Request;
      begin
         Changed (Changed'First + 3) := 16#43#;
         pragma Assert (not S.Is_Sync_Header (Changed, Write_Header),
                        "ProtocolId");
         Passed;
         Changed := Write_Request;
         Changed (Changed'First + 4) := 16#41#;
         pragma Assert (not S.Is_Sync_Header (Changed, Write_Header),
                        "StructureSize");
         Passed;
      end;
      --  Each value of the record is matched against its own field: a
      --  change to any one value no longer matches.
      pragma Assert
        (not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Credit_Charge => 2))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Status => 1))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Command => S.Read))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Credits => 2))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Flags => 0))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Next_Command => 64))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Message_Id => 2 ** 32 + 5))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Reserved => 0))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Tree_Id => 2))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Session_Id => 16#21#))
         and then not S.Is_Sync_Header
           (Write_Request,
            (Write_Header with delta Signature => (15 => 1, others => 0))),
         "each field");
      Passed;
      --  A header needs all 64 bytes.
      pragma Assert
        (not S.Is_Sync_Header
           (Write_Request (Write_Request'First .. Write_Request'First + 62),
            Write_Header),
         "63 bytes");
      Passed;
      --  The command codes and flags of 2.2.1.2's tables.
      pragma Assert
        (S.Negotiate = 0 and then S.Session_Setup = 1 and then S.Logoff = 2
         and then S.Tree_Connect = 3 and then S.Tree_Disconnect = 4
         and then S.Create = 5 and then S.Close = 6 and then S.Flush = 7
         and then S.Read = 8 and then S.Write = 9 and then S.Lock = 16#A#
         and then S.Ioctl = 16#B# and then S.Cancel = 16#C#
         and then S.Echo = 16#D# and then S.Query_Directory = 16#E#
         and then S.Change_Notify = 16#F# and then S.Query_Info = 16#10#
         and then S.Set_Info = 16#11# and then S.Oplock_Break = 16#12#,
         "command codes");
      Passed;
      pragma Assert
        (S.Flags_Server_To_Redir = 16#0000_0001#
         and then S.Flags_Async_Command = 16#0000_0002#
         and then S.Flags_Related_Operations = 16#0000_0004#
         and then S.Flags_Signed = 16#0000_0008#
         and then S.Flags_Priority_Mask = 16#0000_0070#
         and then S.Flags_DFS_Operations = 16#1000_0000#
         and then S.Flags_Replay_Operation = 16#2000_0000#,
         "flags");
      Passed;
      --  A client's own request: no status, NextCommand or Reserved, and
      --  the Signature zero until signing fills it in.
      pragma Assert
        (S.Request_Header
           (Command => S.Write, Credit_Charge => 1, Credit_Request => 1,
            Flags => S.Flags_Signed, Message_Id => 5, Tree_Id => 1,
            Session_Id => 16#0000_1000_0000_0021#)
         = (Write_Header with delta Reserved => 0)
         and then
           S.Request_Header
             (Command => S.Session_Setup, Credit_Charge => 1,
              Credit_Request => 16#80#, Flags => 0, Message_Id => 1,
              Tree_Id => 0, Session_Id => 0)
         = (Setup_Request_Header with delta Reserved => 0),
         "Request_Header");
      Passed;
   end Test_SMB2_Header;
   --  MS-SMB2 2.2.15, 2.2.19 and 2.2.21: the CLOSE, READ and WRITE
   --  requests. The READ and WRITE are the bodies of the blog's A.2
   --  messages above (test_suite decrypts them); where their fields are all
   --  zero, a READ with every field set tells the fields apart, and a CLOSE,
   --  of which no message is published here, is built from the layout.
   procedure Test_SMB2_Transfer is
      package S renames SMB.Spec.SMB2;
      use type SMB.Bytes;
      File_Id : constant SMB.Bytes (0 .. 15) :=
        (16#05#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#);
      Read_Body : constant SMB.Bytes :=
        (16#31#, 16#00#, 16#00#, 16#00#, 16#17#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#)
        & File_Id
        & (16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
           16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
           16#00#);
      Payload : constant SMB.Bytes :=
        (16#53#, 16#6D#, 16#62#, 16#33#, 16#20#, 16#65#, 16#6E#, 16#63#,
         16#72#, 16#79#, 16#70#, 16#74#, 16#69#, 16#6F#, 16#6E#, 16#20#,
         16#74#, 16#65#, 16#73#, 16#74#, 16#69#, 16#6E#, 16#67#);
      Write_Body : constant SMB.Bytes :=
        (16#31#, 16#00#, 16#70#, 16#00#, 16#17#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#)
        & File_Id
        & (16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
           16#70#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#)
        & Payload;
      --  Every READ field set, each to a value of its own whose bytes all
      --  differ, so that a field read at the wrong offset or width differs.
      Full_Read : constant SMB.Bytes (10 .. 58) :=
        (16#31#, 16#00#, 16#50#, 16#01#, 16#04#, 16#03#, 16#02#, 16#01#,
         16#08#, 16#07#, 16#06#, 16#05#, 16#04#, 16#03#, 16#02#, 16#01#)
        & File_Id
        & (16#14#, 16#13#, 16#12#, 16#11#, 16#24#, 16#23#, 16#22#, 16#21#,
           16#34#, 16#33#, 16#32#, 16#31#, 16#42#, 16#41#, 16#52#, 16#51#,
           16#AA#);
      --  The same for WRITE, with its data 8 bytes after the fields
      --  (DataOffset 120), the gap zero.
      Full_Write : constant SMB.Bytes (100 .. 158) :=
        (16#31#, 16#00#, 16#78#, 16#00#, 16#03#, 16#00#, 16#00#, 16#00#,
         16#18#, 16#17#, 16#16#, 16#15#, 16#14#, 16#13#, 16#12#, 16#11#)
        & File_Id
        & (16#24#, 16#23#, 16#22#, 16#21#, 16#34#, 16#33#, 16#32#, 16#31#,
           16#42#, 16#41#, 16#52#, 16#51#, 16#64#, 16#63#, 16#62#, 16#61#,
           0, 0, 0, 0, 0, 0, 0, 0,
           16#AA#, 16#BB#, 16#CC#);
      Full_Payload : constant SMB.Bytes := (16#AA#, 16#BB#, 16#CC#);
      Close_Body : constant SMB.Bytes :=
        (16#18#, 16#00#, 16#02#, 16#01#, 16#00#, 16#00#, 16#00#, 16#00#)
        & File_Id;
      --  The blog's client sends the READ's Padding as 0, not the 0x50 that
      --  MS-SMB2 3.2.4.6 recommends, and a WRITE's WriteChannelInfoOffset as
      --  112, where this client sends 0x50 and 0.
      Blog_Read : constant S.Read_Request :=
        (S.Client_Read (File_Id, 0, 23) with delta Padding => 0)
      with Ghost;
      Blog_Write : constant S.Write_Request :=
        (S.Client_Write (File_Id, 0, 23)
         with delta Write_Channel_Info_Offset => 112)
      with Ghost;
      Full_Read_Request : constant S.Read_Request :=
        (Padding => 16#50#, Flags => 1, Length => 16#0102_0304#,
         Offset => 16#0102_0304_0506_0708#, File_Id => File_Id,
         Minimum_Count => 16#1112_1314#, Channel => 16#2122_2324#,
         Remaining_Bytes => 16#3132_3334#,
         Read_Channel_Info_Offset => 16#4142#,
         Read_Channel_Info_Length => 16#5152#, Buffer => 16#AA#)
      with Ghost;
      Full_Write_Request : constant S.Write_Request :=
        (Data_Offset => 120, Length => 3,
         Offset => 16#1112_1314_1516_1718#, File_Id => File_Id,
         Channel => 16#2122_2324#, Remaining_Bytes => 16#3132_3334#,
         Write_Channel_Info_Offset => 16#4142#,
         Write_Channel_Info_Length => 16#5152#, Flags => 16#6162_6364#)
      with Ghost;
      Full_Close_Request : constant S.Close_Request :=
        (Flags => 16#0102#, File_Id => File_Id)
      with Ghost;
   begin
      pragma Assert (S.Is_Read_Request (Read_Body, Blog_Read),
                     "the blog's READ request");
      Passed;
      pragma Assert
        (not S.Is_Read_Request (Read_Body, S.Client_Read (File_Id, 0, 23))
         and then S.Client_Read (File_Id, 0, 23).Padding = 16#50#
         and then S.Client_Read (File_Id, 0, 23).Buffer = 0,
         "this client's READ: Padding 0x50, Buffer byte 0");
      Passed;
      pragma Assert (S.Is_Read_Request (Full_Read, Full_Read_Request),
                     "a READ with every field set, at other bounds");
      Passed;
      pragma Assert
        (not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Padding => 16#51#))
         and then not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Flags => 0))
         and then not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Length => 1))
         and then not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Offset => 16#0708#))
         and then not S.Is_Read_Request
           (Full_Read,
            (Full_Read_Request with delta
               File_Id => (15 => 5, others => 0)))
         and then not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Minimum_Count => 3))
         and then not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Channel => 0))
         and then not S.Is_Read_Request
           (Full_Read, (Full_Read_Request with delta Remaining_Bytes => 1))
         and then not S.Is_Read_Request
           (Full_Read,
            (Full_Read_Request with delta Read_Channel_Info_Offset => 16#4152#))
         and then not S.Is_Read_Request
           (Full_Read,
            (Full_Read_Request with delta Read_Channel_Info_Length => 16#4142#))
         and then not S.Is_Read_Request
           (Full_Read (10 .. 57), Full_Read_Request),
         "each READ field");
      Passed;
      pragma Assert
        (S.Is_Write_Request (Full_Write, Full_Write_Request, Full_Payload),
         "a WRITE with every field set, its data after a gap");
      Passed;
      pragma Assert
        (S.Is_Close_Request (Close_Body, Full_Close_Request),
         "a CLOSE with Flags set");
      Passed;
      --  Every byte is fixed: changing any one breaks the match. A field
      --  read at another offset or width, a check left out, the gap or the
      --  data read elsewhere, all fail here.
      for Index in Full_Read'Range loop
         declare
            Changed : SMB.Bytes := Full_Read;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (not S.Is_Read_Request (Changed, Full_Read_Request),
               "every READ byte");
         end;
      end loop;
      Passed;
      for Index in Full_Write'Range loop
         declare
            Changed : SMB.Bytes := Full_Write;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (not S.Is_Write_Request
                 (Changed, Full_Write_Request, Full_Payload),
               "every WRITE byte");
         end;
      end loop;
      Passed;
      for Index in Close_Body'Range loop
         declare
            Changed : SMB.Bytes := Close_Body;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (not S.Is_Close_Request (Changed, Full_Close_Request),
               "every CLOSE byte");
         end;
      end loop;
      Passed;
      --  The data starts after the fields, never inside them.
      pragma Assert
        (not S.Is_Write_Request
           (Write_Body (0 .. 47) & Payload,
            (Blog_Write with delta Data_Offset => 64 + 40),
            Write_Body (40 .. 47) & Payload),
         "data inside the fields");
      Passed;
      pragma Assert (S.Is_Write_Request (Write_Body, Blog_Write, Payload),
                     "the blog's WRITE request");
      Passed;
      pragma Assert
        (S.Is_Write_Fields (Write_Body, Blog_Write)
         and then not S.Is_Write_Request
           (Write_Body, S.Client_Write (File_Id, 0, 23), Payload)
         and then not S.Is_Write_Request
           (Write_Body, Blog_Write, Payload (1 .. 22))
         and then not S.Is_Write_Request
           (Write_Body, (Blog_Write with delta Data_Offset => 113), Payload)
         and then not S.Is_Write_Request
           (Write_Body, (Blog_Write with delta Length => 22), Payload)
         and then not S.Is_Write_Request
           (Write_Body, (Blog_Write with delta Offset => 1), Payload)
         and then not S.Is_Write_Request
           (Write_Body, (Blog_Write with delta Flags => 1), Payload),
         "the WRITE's fields and data");
      Passed;
      pragma Assert
        (S.Close_Flag_Postquery_Attrib = 1
         and then not S.Is_Close_Request
           (Close_Body,
            (Flags => S.Close_Flag_Postquery_Attrib, File_Id => File_Id))
         and then not S.Is_Close_Request
           (Close_Body (Close_Body'First .. Close_Body'Last - 1),
            Full_Close_Request),
         "a CLOSE request");
      Passed;
      pragma Assert
        (S.Read_Request_Size = 49 and then S.Write_Request_Size = 49
         and then S.Close_Request_Size = 24
         and then S.Client_Write (File_Id, 0, 0).Data_Offset = 112,
         "structure sizes");
      Passed;
   end Test_SMB2_Transfer;
   --  MS-SMB2 2.2.5, 2.2.9, 2.2.7 and 2.2.11: SESSION_SETUP, TREE_CONNECT,
   --  LOGOFF and TREE_DISCONNECT. The SESSION_SETUP is the first request of
   --  the blog's A.1 (test_suite's A1_Setup_Request_1); the TREE_CONNECT is
   --  MS-SMB2 4.1's, to \\smb2server\IPC$, which the standard gives field by
   --  field; LOGOFF is 4.7's. Requests whose fields all hold distinct
   --  multi-byte values, every byte flipped in turn, fix every byte.
   procedure Test_SMB2_Session is
      package S renames SMB.Spec.SMB2;
      use type SMB.Bytes;
      use type S.Session_Setup_Request;
      Token : constant SMB.Bytes :=
        (16#60#, 16#48#, 16#06#, 16#06#, 16#2B#, 16#06#, 16#01#, 16#05#,
        16#05#, 16#02#, 16#A0#, 16#3E#, 16#30#, 16#3C#, 16#A0#, 16#0E#,
        16#30#, 16#0C#, 16#06#, 16#0A#, 16#2B#, 16#06#, 16#01#, 16#04#,
        16#01#, 16#82#, 16#37#, 16#02#, 16#02#, 16#0A#, 16#A2#, 16#2A#,
        16#04#, 16#28#, 16#4E#, 16#54#, 16#4C#, 16#4D#, 16#53#, 16#53#,
        16#50#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#, 16#97#, 16#82#,
        16#08#, 16#E2#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
        16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
        16#00#, 16#00#, 16#06#, 16#03#, 16#80#, 16#25#, 16#00#, 16#00#,
        16#00#, 16#0F#);
      Setup_Body : constant SMB.Bytes :=
        (16#19#, 16#00#, 16#00#, 16#01#, 16#01#, 16#00#, 16#00#, 16#00#,
        16#00#, 16#00#, 16#00#, 16#00#, 16#58#, 16#00#, 16#4A#, 16#00#,
        16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#)
        & Token;
      Path : constant SMB.Bytes :=
        (16#5C#, 16#00#, 16#5C#, 16#00#, 16#73#, 16#00#, 16#6D#, 16#00#,
        16#62#, 16#00#, 16#32#, 16#00#, 16#73#, 16#00#, 16#65#, 16#00#,
        16#72#, 16#00#, 16#76#, 16#00#, 16#65#, 16#00#, 16#72#, 16#00#,
        16#5C#, 16#00#, 16#49#, 16#00#, 16#50#, 16#00#, 16#43#, 16#00#,
        16#24#, 16#00#);
      Tree_Body : constant SMB.Bytes (200 .. 207) :=
        (16#09#, 16#00#, 16#00#, 16#00#, 16#48#, 16#00#, 16#22#, 16#00#);
      Logoff_Body : constant SMB.Bytes := (16#04#, 16#00#, 16#00#, 16#00#);
      --  SecurityBufferOffset 92 leaves 4 bytes between the fields and the
      --  token; PathOffset 76 leaves 4 before the path.
      Full_Setup : constant SMB.Bytes (300 .. 330) :=
        (16#19#, 16#00#, 16#81#, 16#42#, 16#14#, 16#13#, 16#12#, 16#11#,
        16#24#, 16#23#, 16#22#, 16#21#, 16#5C#, 16#00#, 16#03#, 16#00#,
        16#38#, 16#37#, 16#36#, 16#35#, 16#34#, 16#33#, 16#32#, 16#31#)
        & (16#00#, 16#00#, 16#00#, 16#00#)
        & (16#AA#, 16#BB#, 16#CC#);
      Full_Token : constant SMB.Bytes := (16#AA#, 16#BB#, 16#CC#);
      Full_Tree : constant SMB.Bytes :=
        (16#09#, 16#00#, 16#52#, 16#51#, 16#4C#, 16#00#, 16#04#, 16#00#)
        & (16#00#, 16#00#, 16#00#, 16#00#)
        & (16#41#, 16#00#, 16#42#, 16#00#);
      Full_Path : constant SMB.Bytes := (16#41#, 16#00#, 16#42#, 16#00#);
      Blog_Setup : constant S.Session_Setup_Request :=
        (Flags => 0, Security_Mode => S.Negotiate_Signing_Enabled,
         Capabilities => 1, Channel => 0, Security_Buffer_Offset => 88,
         Security_Buffer_Length => 16#4A#, Previous_Session_Id => 0)
      with Ghost;
      Full_Setup_Request : constant S.Session_Setup_Request :=
        (Flags => 16#81#, Security_Mode => 16#42#,
         Capabilities => 16#1112_1314#, Channel => 16#2122_2324#,
         Security_Buffer_Offset => 92, Security_Buffer_Length => 3,
         Previous_Session_Id => 16#3132_3334_3536_3738#)
      with Ghost;
      Full_Tree_Request : constant S.Tree_Connect_Request :=
        (Flags => 16#5152#, Path_Offset => 76, Path_Length => 4)
      with Ghost;
   begin
      pragma Assert
        (S.Is_Session_Setup_Request (Setup_Body, Blog_Setup, Token)
         and then not S.Is_Session_Setup_Request
           (Setup_Body, S.Client_Session_Setup (16#4A#), Token),
         "the blog's SESSION_SETUP request");
      Passed;
      --  This client: signing required and enabled, no DFS, the token at 88.
      pragma Assert
        (S.Client_Session_Setup (16#4A#)
         = (Blog_Setup with delta
              Security_Mode =>
                S.Negotiate_Signing_Enabled + S.Negotiate_Signing_Required,
              Capabilities => 0),
         "this client's SESSION_SETUP");
      Passed;
      pragma Assert
        (S.Is_Tree_Connect_Request
           (Tree_Body & Path, S.Client_Tree_Connect (34), Path)
         and then not S.Is_Tree_Connect_Request
           (Tree_Body & Path, S.Client_Tree_Connect (34),
            Path (Path'First .. Path'Last - 2)),
         "MS-SMB2 4.1's TREE_CONNECT request");
      Passed;
      pragma Assert
        (S.Is_Logoff_Request (Logoff_Body)
         and then S.Is_Tree_Disconnect_Request (Logoff_Body)
         and then not S.Is_Logoff_Request
           (Logoff_Body (Logoff_Body'First .. Logoff_Body'Last - 1)),
         "MS-SMB2 4.7's LOGOFF request");
      Passed;
      pragma Assert
        (S.Is_Session_Setup_Request (Full_Setup, Full_Setup_Request, Full_Token)
         and then S.Is_Tree_Connect_Request
           (Full_Tree, Full_Tree_Request, Full_Path),
         "requests with every field set");
      Passed;
      for Index in Full_Setup'Range loop
         declare
            Changed : SMB.Bytes := Full_Setup;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            --  The 4 bytes before the token are not part of the request.
            pragma Assert
              (Index in Full_Setup'First + 24 .. Full_Setup'First + 27
               or else not S.Is_Session_Setup_Request
                 (Changed, Full_Setup_Request, Full_Token),
               "every SESSION_SETUP byte");
         end;
      end loop;
      Passed;
      for Index in Full_Tree'Range loop
         declare
            Changed : SMB.Bytes := Full_Tree;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (Index in Full_Tree'First + 8 .. Full_Tree'First + 11
               or else not S.Is_Tree_Connect_Request
                 (Changed, Full_Tree_Request, Full_Path),
               "every TREE_CONNECT byte");
         end;
      end loop;
      Passed;
      for Index in Logoff_Body'Range loop
         declare
            Changed : SMB.Bytes := Logoff_Body;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (not S.Is_Logoff_Request (Changed)
               and then not S.Is_Tree_Disconnect_Request (Changed),
               "every LOGOFF byte");
         end;
      end loop;
      Passed;
      pragma Assert
        (S.Session_Setup_Request_Size = 25 and then S.Tree_Connect_Request_Size = 9
         and then S.Logoff_Request_Size = 4
         and then S.Tree_Disconnect_Request_Size = 4
         and then S.Negotiate_Signing_Enabled = 1
         and then S.Negotiate_Signing_Required = 2,
         "structure sizes and security modes");
      Passed;
   end Test_SMB2_Session;
begin
   Test_Encoding;
   Test_SMB2_Header;
   Test_SMB2_Transfer;
   Test_SMB2_Session;
   Ada.Text_IO.Put_Line
     ("specification tests passed:" & Natural'Image (Checks) & " checks");
end Spec_Test;
