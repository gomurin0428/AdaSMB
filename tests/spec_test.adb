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
with SMB.Spec.FSCC;
with SMB.Spec.SMB2;
with SMB.Spec.SMB2.Negotiation;

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
      --  SecurityBufferLength is the token's length, and an offset never
      --  points into the fields.
      declare
         Overlap : SMB.Bytes := Full_Setup;
         Tree_Overlap : SMB.Bytes := Full_Tree;
      begin
         Overlap (Overlap'First + 12) := 16#50#;
         Tree_Overlap (Tree_Overlap'First + 4) := 16#42#;
         pragma Assert
           (not S.Is_Session_Setup_Request
              (Setup_Body, Blog_Setup, Token (Token'First .. Token'Last - 1))
            and then not S.Is_Session_Setup_Request
              (Overlap,
               (Full_Setup_Request with delta Security_Buffer_Offset => 80),
               SMB.Bytes'(16#38#, 16#37#, 16#36#))
            and then not S.Is_Tree_Connect_Request
              (Tree_Overlap,
               (Full_Tree_Request with delta Path_Offset => 66),
               SMB.Bytes'(16#52#, 16#51#, 16#42#, 16#00#)),
            "SecurityBufferLength, and offsets into the fields");
      end;
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
   --  MS-SMB2 2.2.13 and 2.2.33: CREATE and QUERY_DIRECTORY. No message is
   --  published here for either, so the vectors are built from the layout,
   --  every field a distinct multi-byte value, the name and the pattern
   --  after a 4-byte gap; every byte flipped in turn (but the gap's) breaks
   --  the match.
   procedure Test_SMB2_Create is
      package S renames SMB.Spec.SMB2;
      use type SMB.Bytes;
      use type S.Create_Request;
      use type S.Query_Directory_Request;
      File_Id : constant SMB.Bytes (0 .. 15) :=
        (16#05#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#01#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#);
      Name : constant SMB.Bytes := (16#41#, 16#00#, 16#42#, 16#00#);
      Full_Create : constant SMB.Bytes (400 .. 467) :=
        (16#39#, 16#00#, 16#81#, 16#42#, 16#14#, 16#13#, 16#12#, 16#11#,
        16#28#, 16#27#, 16#26#, 16#25#, 16#24#, 16#23#, 16#22#, 16#21#,
        16#38#, 16#37#, 16#36#, 16#35#, 16#34#, 16#33#, 16#32#, 16#31#,
        16#44#, 16#43#, 16#42#, 16#41#, 16#54#, 16#53#, 16#52#, 16#51#,
        16#64#, 16#63#, 16#62#, 16#61#, 16#74#, 16#73#, 16#72#, 16#71#,
        16#84#, 16#83#, 16#82#, 16#81#, 16#80#, 16#00#, 16#04#, 16#00#,
        16#94#, 16#93#, 16#92#, 16#91#, 16#A4#, 16#A3#, 16#A2#, 16#A1#)
        & (0, 0, 0, 0, 0, 0, 0, 0) & Name;
      Full_Query : constant SMB.Bytes :=
        (16#21#, 16#00#, 16#26#, 16#05#, 16#14#, 16#13#, 16#12#, 16#11#,
        16#05#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#01#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#64#, 16#00#, 16#02#, 16#00#, 16#24#, 16#23#, 16#22#, 16#21#)
        & (0, 0, 0, 0) & (16#2A#, 16#00#);
      Full_Create_Request : constant S.Create_Request :=
        (Security_Flags => 16#81#, Requested_Oplock_Level => 16#42#,
         Impersonation_Level => 16#1112_1314#,
         Smb_Create_Flags => 16#2122_2324_2526_2728#,
         Reserved => 16#3132_3334_3536_3738#,
         Desired_Access => 16#4142_4344#, File_Attributes => 16#5152_5354#,
         Share_Access => 16#6162_6364#, Create_Disposition => 16#7172_7374#,
         Create_Options => 16#8182_8384#, Name_Offset => 128,
         Name_Length => 4, Create_Contexts_Offset => 16#9192_9394#,
         Create_Contexts_Length => 16#A1A2_A3A4#)
      with Ghost;
      Full_Query_Request : constant S.Query_Directory_Request :=
        (File_Information_Class => 16#26#, Flags => 16#05#,
         File_Index => 16#1112_1314#, File_Id => File_Id,
         File_Name_Offset => 100, File_Name_Length => 2,
         Output_Buffer_Length => 16#2122_2324#)
      with Ghost;
   begin
      pragma Assert
        (S.Is_Create_Request (Full_Create, Full_Create_Request, Name)
         and then S.Is_Query_Directory_Request
           (Full_Query, Full_Query_Request, S.Every_Name),
         "CREATE and QUERY_DIRECTORY with every field set");
      Passed;
      for Index in Full_Create'Range loop
         declare
            Changed : SMB.Bytes := Full_Create;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (Index in Full_Create'First + 56 .. Full_Create'First + 63
               or else not S.Is_Create_Request
                 (Changed, Full_Create_Request, Name),
               "every CREATE byte");
         end;
      end loop;
      Passed;
      for Index in Full_Query'Range loop
         declare
            Changed : SMB.Bytes := Full_Query;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (Index in Full_Query'First + 32 .. Full_Query'First + 35
               or else not S.Is_Query_Directory_Request
                 (Changed, Full_Query_Request, S.Every_Name),
               "every QUERY_DIRECTORY byte");
         end;
      end loop;
      Passed;
      --  NameLength and FileNameLength are the lengths of what follows; an
      --  offset into the fields is refused even when the data says so and
      --  the bytes there are the name; the name is 8-byte aligned; Buffer
      --  has at least one byte; with no pattern, FileNameOffset and
      --  FileNameLength are 0.
      declare
         Create_Overlap : SMB.Bytes := Full_Create;
         Unaligned : SMB.Bytes := Full_Create;
         Query_Overlap : SMB.Bytes := Full_Query;
         No_Pattern : SMB.Bytes := Full_Query (Full_Query'First .. Full_Query'First + 31);
         Short_Create : SMB.Bytes :=
           Full_Create (Full_Create'First .. Full_Create'First + 55);
         Empty : constant SMB.Bytes (1 .. 0) := (others => 0);
      begin
         Create_Overlap (Create_Overlap'First + 44) := 16#70#;
         Unaligned (Unaligned'First + 44) := 16#84#;
         Query_Overlap (Query_Overlap'First + 24) := 16#5C#;
         No_Pattern (No_Pattern'First + 24) := 0;
         No_Pattern (No_Pattern'First + 26) := 0;
         Short_Create (Short_Create'First + 44) := 16#78#;
         Short_Create (Short_Create'First + 46) := 0;
         pragma Assert
           (not S.Is_Create_Request
              (Full_Create, Full_Create_Request,
               Name (Name'First .. Name'Last - 2))
            and then not S.Is_Create_Request
              (Create_Overlap,
               (Full_Create_Request with delta Name_Offset => 112),
               SMB.Bytes'(16#94#, 16#93#, 16#92#, 16#91#))
            and then not S.Is_Create_Request
              (Unaligned, (Full_Create_Request with delta Name_Offset => 132),
               SMB.Bytes'(0, 0, 0, 0))
            and then S.Is_Create_Request
              (Short_Create & (0 => 0),
               (Full_Create_Request with delta
                  Name_Offset => 120, Name_Length => 0), Empty)
            and then not S.Is_Create_Request
              (Short_Create,
               (Full_Create_Request with delta
                  Name_Offset => 120, Name_Length => 0), Empty)
            and then not S.Is_Query_Directory_Request
              (Full_Query & (0, 0), Full_Query_Request,
               SMB.Bytes'(16#2A#, 16#00#, 0, 0))
            and then not S.Is_Query_Directory_Request
              (Query_Overlap,
               (Full_Query_Request with delta File_Name_Offset => 92),
               SMB.Bytes'(16#24#, 16#23#))
            and then S.Is_Query_Directory_Request
              (No_Pattern,
               (Full_Query_Request with delta
                  File_Name_Offset => 0, File_Name_Length => 0), Empty)
            and then not S.Is_Query_Directory_Request
              (Full_Query (Full_Query'First .. Full_Query'First + 31),
               (Full_Query_Request with delta File_Name_Length => 0), Empty),
            "lengths, offsets into the fields, alignment, empty parts");
      end;
      Passed;
      --  This client's CREATE: a file and a directory.
      pragma Assert
        (S.Client_Create (16#0012_0089#, S.File_Open_If, False, 4)
         = (Security_Flags => 0, Requested_Oplock_Level => S.Oplock_Level_None,
            Impersonation_Level => S.Impersonation, Smb_Create_Flags => 0,
            Reserved => 0, Desired_Access => 16#0012_0089#,
            File_Attributes => 0, Share_Access => 7,
            Create_Disposition => 3, Create_Options => 16#40#,
            Name_Offset => 120, Name_Length => 4,
            Create_Contexts_Offset => 0, Create_Contexts_Length => 0)
         and then S.Client_Create (16#0010_0080#, S.File_Create, True, 6)
           = (Security_Flags => 0, Requested_Oplock_Level => 0,
              Impersonation_Level => 2, Smb_Create_Flags => 0, Reserved => 0,
              Desired_Access => 16#0010_0080#, File_Attributes => 16#10#,
              Share_Access => 7, Create_Disposition => 2,
              Create_Options => 1, Name_Offset => 120, Name_Length => 6,
              Create_Contexts_Offset => 0, Create_Contexts_Length => 0),
         "this client's CREATE");
      Passed;
      pragma Assert
        (S.Client_Query_Directory (File_Id, True)
         = (File_Information_Class => 16#25#, Flags => 1, File_Index => 0,
            File_Id => File_Id, File_Name_Offset => 96,
            File_Name_Length => 2, Output_Buffer_Length => 65_536)
         and then S.Client_Query_Directory (File_Id, False).Flags = 0,
         "this client's QUERY_DIRECTORY");
      Passed;
      pragma Assert
        (S.Create_Request_Size = 57 and then S.Query_Directory_Request_Size = 33
         and then S.Impersonation = 2 and then S.File_Open = 1
         and then S.File_Create = 2 and then S.File_Open_If = 3
         and then S.File_Directory_File = 1
         and then S.File_Non_Directory_File = 16#40#
         and then S.File_Attribute_Directory = 16#10#
         and then S.File_Id_Both_Directory_Information = 16#25#
         and then S.Restart_Scans = 1 and then S.Oplock_Level_None = 0,
         "structure sizes and constants");
      Passed;
   end Test_SMB2_Create;
   --  MS-SMB2 2.2.37 and 2.2.39 (QUERY_INFO, SET_INFO) and the MS-FSCC 2.4
   --  structures this client sends. The SET_INFO is MS-SMB2 4.6's, which
   --  sets FileEndOfFileInformation and gives every field (EndOfFile
   --  0x2F000 on FileId 0x19, 0xFFFFFFFF00000005); the others are built
   --  from the layouts, every field a distinct multi-byte value, every byte
   --  flipped in turn.
   procedure Test_SMB2_Info is
      package S renames SMB.Spec.SMB2;
      package F renames SMB.Spec.FSCC;
      use type SMB.Bytes;
      use type S.Query_Info_Request;
      use type S.Set_Info_Request;
      End_Of_File_Body : constant SMB.Bytes :=
        (16#21#, 16#00#, 16#01#, 16#14#, 16#08#, 16#00#, 16#00#, 16#00#,
        16#60#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
        16#19#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
        16#05#, 16#00#, 16#00#, 16#00#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
        16#00#, 16#F0#, 16#02#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      Id_461 : constant SMB.Bytes (0 .. 15) :=
        (16#19#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
        16#05#, 16#00#, 16#00#, 16#00#, 16#FF#, 16#FF#, 16#FF#, 16#FF#);
      File_Id : constant SMB.Bytes (0 .. 15) :=
        (16#05#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#01#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#);
      Full_Query : constant SMB.Bytes (500 .. 540) :=
        (16#29#, 16#00#, 16#02#, 16#22#, 16#14#, 16#13#, 16#12#, 16#11#,
        16#22#, 16#21#, 16#32#, 16#31#, 16#44#, 16#43#, 16#42#, 16#41#,
        16#54#, 16#53#, 16#52#, 16#51#, 16#64#, 16#63#, 16#62#, 16#61#,
        16#05#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#01#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#AA#);
      --  BufferOffset 104: 8 bytes between the fields and the information.
      Full_Set : constant SMB.Bytes :=
        (16#21#, 16#00#, 16#02#, 16#0A#, 16#03#, 16#00#, 16#00#, 16#00#,
        16#68#, 16#00#, 16#72#, 16#71#, 16#84#, 16#83#, 16#82#, 16#81#,
        16#05#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#,
        16#01#, 16#00#, 16#00#, 16#00#, 16#04#, 16#00#, 16#00#, 16#00#)
        & (0, 0, 0, 0, 0, 0, 0, 0) & (16#41#, 16#42#, 16#43#);
      Full_Query_Request : constant S.Query_Info_Request :=
        (Info_Type => 2, File_Info_Class => 16#22#,
         Output_Buffer_Length => 16#1112_1314#,
         Input_Buffer_Offset => 16#2122#, Reserved => 16#3132#,
         Input_Buffer_Length => 16#4142_4344#,
         Additional_Information => 16#5152_5354#, Flags => 16#6162_6364#,
         File_Id => File_Id)
      with Ghost;
      Full_Set_Request : constant S.Set_Info_Request :=
        (Info_Type => 2, File_Info_Class => 16#0A#, Buffer_Length => 3,
         Buffer_Offset => 104, Reserved => 16#7172#,
         Additional_Information => 16#8182_8384#, File_Id => File_Id)
      with Ghost;
      --  FILE_RENAME_INFORMATION_TYPE_2 for the one-character name "b":
      --  20 bytes, the name, 2 bytes of padding.
      Rename_B : constant SMB.Bytes :=
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         16#02#, 0, 0, 0, 16#62#, 0, 0, 0);
      Rename_Long : constant SMB.Bytes :=
        (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         16#06#, 0, 0, 0, 16#61#, 0, 16#62#, 0, 16#63#, 0);
      --  The same bytes at indices that do not start at 0, as the
      --  predicates must read from Data'First.
      End_Of_File_High : constant SMB.Bytes (300 .. 339) := End_Of_File_Body;
      Rename_B_High : constant SMB.Bytes (700 .. 723) := Rename_B;
   begin
      pragma Assert
        (S.Is_Set_Info_Request
           (End_Of_File_Body,
            S.Client_Set_Info (F.File_End_Of_File_Information, 8, Id_461),
            End_Of_File_Body (32 .. 39))
         and then F.Is_End_Of_File_Information
           (End_Of_File_Body (32 .. 39), 16#2_F000#),
         "MS-SMB2 4.6's SET_INFO FileEndOfFileInformation");
      Passed;
      pragma Assert
        (S.Is_Set_Info_Request
           (End_Of_File_High,
            S.Client_Set_Info (F.File_End_Of_File_Information, 8, Id_461),
            End_Of_File_High (332 .. 339))
         and then F.Is_End_Of_File_Information
           (End_Of_File_High (332 .. 339), 16#2_F000#)
         and then F.Is_Rename_Information
           (Rename_B_High, False, SMB.Bytes'(16#62#, 0)),
         "SET_INFO and its information at high indices");
      Passed;
      pragma Assert
        (S.Is_Query_Info_Request (Full_Query, Full_Query_Request)
         and then S.Is_Set_Info_Request
           (Full_Set, Full_Set_Request,
            SMB.Bytes'(16#41#, 16#42#, 16#43#)),
         "QUERY_INFO and SET_INFO with every field set");
      Passed;
      for Index in Full_Query'Range loop
         declare
            Changed : SMB.Bytes := Full_Query;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            --  The byte of Buffer is not part of the request's fields.
            pragma Assert
              (Index = Full_Query'Last
               or else not S.Is_Query_Info_Request
                 (Changed, Full_Query_Request),
               "every QUERY_INFO byte");
         end;
      end loop;
      Passed;
      --  The byte of Buffer that StructureSize counts is not required.
      pragma Assert
        (S.Is_Query_Info_Request (Full_Query (500 .. 539), Full_Query_Request)
         and then not S.Is_Query_Info_Request
           (Full_Query (500 .. 538), Full_Query_Request),
         "QUERY_INFO: 40 bytes of fields");
      Passed;
      for Index in Full_Set'Range loop
         declare
            Changed : SMB.Bytes := Full_Set;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            pragma Assert
              (Index in Full_Set'First + 32 .. Full_Set'First + 39
               or else not S.Is_Set_Info_Request
                 (Changed, Full_Set_Request,
                  SMB.Bytes'(16#41#, 16#42#, 16#43#)),
               "every SET_INFO byte");
         end;
      end loop;
      Passed;
      --  BufferLength is the information's length, and BufferOffset never
      --  points into the fields.
      declare
         Overlap : SMB.Bytes := Full_Set;
      begin
         Overlap (Overlap'First + 8) := 16#5C#;
         pragma Assert
           (not S.Is_Set_Info_Request
              (Full_Set, Full_Set_Request, SMB.Bytes'(16#41#, 16#42#))
            and then not S.Is_Set_Info_Request
              (Overlap, (Full_Set_Request with delta Buffer_Offset => 92),
               SMB.Bytes'(16#04#, 16#00#, 16#00#)),
            "BufferLength, and an offset into the fields");
      end;
      Passed;
      --  The information structures.
      pragma Assert
        (F.Is_Disposition_Information (SMB.Bytes'(0 => 1), True)
         and then F.Is_Disposition_Information (SMB.Bytes'(0 => 0), False)
         and then not F.Is_Disposition_Information (SMB.Bytes'(0 => 1), False)
         and then not F.Is_Disposition_Information (SMB.Bytes'(0, 0), False),
         "FileDispositionInformation");
      Passed;
      pragma Assert
        (F.Is_End_Of_File_Information
           (SMB.Bytes'(16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
                       16#FF#, 16#7F#), 2 ** 63 - 1)
         and then not F.Is_End_Of_File_Information
           (SMB.Bytes'(0, 0, 0, 0, 0, 0, 0, 16#80#), 2 ** 63)
         and then not F.Is_End_Of_File_Information
           (SMB.Bytes'(0, 16#F0#, 2, 0, 0, 0, 0), 16#2_F000#)
         and then not F.Is_End_Of_File_Information
           (SMB.Bytes'(0, 16#F0#, 2, 0, 0, 0, 0, 0, 0), 16#2_F000#),
         "FileEndOfFileInformation: signed, 8 bytes");
      Passed;
      pragma Assert
        (F.Is_Rename_Information (Rename_B, False, SMB.Bytes'(16#62#, 0))
         and then not F.Is_Rename_Information
           (Rename_B (Rename_B'First .. Rename_B'Last - 2), False,
            SMB.Bytes'(16#62#, 0))
         and then F.Is_Rename_Information
           (Rename_Long, True, SMB.Bytes'(16#61#, 0, 16#62#, 0, 16#63#, 0))
         and then not F.Is_Rename_Information
           (Rename_Long, False, SMB.Bytes'(16#61#, 0, 16#62#, 0, 16#63#, 0))
         and then F.Rename_Information_Length (2) = 24
         and then F.Rename_Information_Length (6) = 26,
         "FILE_RENAME_INFORMATION_TYPE_2, padded to 24 bytes");
      Passed;
      --  No more padding than 24 bytes need (the standard's MUST; older
      --  Windows clients sent up to 4 more, endnote <161>), and any nonzero
      --  ReplaceIfExists is TRUE (MS-FSCC 2.1.8).
      pragma Assert
        (not F.Is_Rename_Information
           (Rename_Long & SMB.Bytes'(0, 0), True,
            SMB.Bytes'(16#61#, 0, 16#62#, 0, 16#63#, 0))
         and then not F.Is_Rename_Information
           (Rename_B & SMB.Bytes'(0, 0), False, SMB.Bytes'(16#62#, 0))
         and then F.Is_Rename_Information
           (SMB.Bytes'(0 => 2) & Rename_Long (Rename_Long'First + 1
                                               .. Rename_Long'Last),
            True, SMB.Bytes'(16#61#, 0, 16#62#, 0, 16#63#, 0)),
         "FILE_RENAME_INFORMATION_TYPE_2: exact padding, a Boolean");
      Passed;
      for Index in Rename_Long'Range loop
         declare
            Changed : SMB.Bytes := Rename_Long;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            --  The Reserved bytes "can contain any value".
            pragma Assert
              (Index in Rename_Long'First + 1 .. Rename_Long'First + 7
               or else not F.Is_Rename_Information
                 (Changed, True, SMB.Bytes'(16#61#, 0, 16#62#, 0, 16#63#, 0)),
               "every FILE_RENAME_INFORMATION byte");
         end;
      end loop;
      Passed;
      --  This client's requests and the classes.
      pragma Assert
        (S.Client_Query_Info (34, 56, File_Id)
         = (Info_Type => 1, File_Info_Class => 34, Output_Buffer_Length => 56,
            Input_Buffer_Offset => 0, Reserved => 0, Input_Buffer_Length => 0,
            Additional_Information => 0, Flags => 0, File_Id => File_Id)
         and then S.Client_Set_Info (13, 1, File_Id)
           = (Info_Type => 1, File_Info_Class => 13, Buffer_Length => 1,
              Buffer_Offset => 96, Reserved => 0, Additional_Information => 0,
              File_Id => File_Id)
         and then S.Info_File = 1
         and then S.Query_Info_Request_Size = 41
         and then S.Set_Info_Request_Size = 33
         and then F.File_Disposition_Information = 13
         and then F.File_End_Of_File_Information = 20
         and then F.File_Rename_Information = 10
         and then F.File_Network_Open_Information = 34
         and then F.Network_Open_Information_Size = 56,
         "this client's QUERY_INFO and SET_INFO, and the classes");
      Passed;
   end Test_SMB2_Info;

   --  The bytes a string of hexadecimal digits spells, from index 0.
   function Hex (Text : String) return SMB.Bytes is
      function Digit (Char : Character) return SMB.Byte is
        (case Char is
            when '0' .. '9' =>
              SMB.Byte (Character'Pos (Char) - Character'Pos ('0')),
            when 'A' .. 'F' =>
              SMB.Byte (Character'Pos (Char) - Character'Pos ('A') + 10),
            when others => raise Program_Error);
      Result : SMB.Bytes (0 .. Text'Length / 2 - 1);
   begin
      for Index in Result'Range loop
         Result (Index) :=
           Digit (Text (Text'First + 2 * Index)) * 16
           + Digit (Text (Text'First + 2 * Index + 1));
      end loop;
      return Result;
   end Hex;

   --  MS-SMB2 2.2.3 and 2.2.3.1: the NEGOTIATE request and its contexts.
   procedure Test_SMB2_Negotiate is
      package N renames SMB.Spec.SMB2.Negotiation;
      use type SMB.Bytes;
      use type N.Word_List;
      use type N.Negotiate_Request;
      --  The NEGOTIATE requests of Windows 10 in "SMB 3.1.1
      --  Pre-authentication integrity in Windows 10" (Microsoft Open
      --  Specifications blog, 2015), appendices A.1, A.2 and B, after the
      --  64-byte header: five dialects, SecurityMode 0, Capabilities 0x3F,
      --  the contexts at offset 0x70.
      Windows_Fields : constant String :=
        "24000500000000003F000000";
      Body_A1 : constant SMB.Bytes :=
        Hex (Windows_Fields & "ECD86F326276024F9F7752B89BB33F3A"
             & "70000000" & "0200" & "0000" & "02021002000302031103" & "0000"
             & "0100260000000000" & "010020000100"
             & "FA49E6578F1F3A9F4CD3E9CC14A67AA8"
             & "84B3D05844E0E5A118225C15887F32FF"
             & "0000"
             & "0200060000000000" & "020002000100");
      Body_A2 : constant SMB.Bytes :=
        Hex (Windows_Fields & "C318232F0EDFFB4D99991F725DA93B3E"
             & "70000000" & "0200" & "0000" & "02021002000302031103" & "0000"
             & "0100260000000000" & "010020000100"
             & "BE43C3C288C4D3992CD82559E382F0AA"
             & "CEB5A1D936A1BFF07AD1E0C18DB0CA86"
             & "0000"
             & "0200040000000000" & "01000100");
      Body_B : constant SMB.Bytes :=
        Hex (Windows_Fields & "4C3DB6FB51377A45AB915E5700F9D91B"
             & "70000000" & "0100" & "0000" & "02021002000302031103" & "0000"
             & "0100260000000000" & "010020000100"
             & "E2D024DB75ED67B6323EDB6BD24FC4C9"
             & "7ECD893481CE1BEFDBD1DE3D09DF9DB5");
      Windows_Request : constant N.Negotiate_Request :=
        (Dialect_Count => 5, Security_Mode => 0, Capabilities => 16#3F#,
         Negotiate_Context_Offset => 16#70#, Negotiate_Context_Count => 2)
      with Ghost;
      Windows_Dialect_List : constant N.Word_List :=
        (N.Dialect_0202, N.Dialect_0210, N.Dialect_0300, N.Dialect_0302,
         N.Dialect_0311)
      with Ghost;

      --  This client's request, with a GUID and a salt whose bytes all
      --  differ: 3.1.1 alone, then with 2.1.
      Guid : constant SMB.Bytes := Hex ("101112131415161718191A1B1C1D1E1F");
      Salt : constant SMB.Bytes :=
        Hex ("202122232425262728292A2B2C2D2E2F"
             & "303132333435363738393A3B3C3D3E3F");
      function Client_Body (Allow_21 : Boolean) return SMB.Bytes is
        (Hex ("2400" & (if Allow_21 then "0200" else "0100") & "0300"
              & "0000" & "44000000")
         & Guid
         & Hex ("68000000" & "0300" & "0000" & "1103"
                & (if Allow_21 then "1002" else "0000")
                & "0100260000000000" & "010020000100")
         & Salt
         & Hex ("0000"
                & "0200" & "0A00" & "00000000" & "0400" & "0200" & "0100"
                & "0400" & "0300" & "000000000000"
                & "0800" & "0600" & "00000000" & "0200" & "0200" & "0100"));
      Client_Only_311 : constant SMB.Bytes := Client_Body (False);
      Client_With_21 : constant SMB.Bytes := Client_Body (True);
      Client_High : constant SMB.Bytes (1000 .. 1125) := Client_Only_311;
   begin
      pragma Assert
        (Body_A1'Length = 110
         and then N.Is_Negotiate_Request
           (Body_A1, Windows_Request, Body_A1 (12 .. 27),
            Windows_Dialect_List)
         and then N.First_Context (5) = 48
         and then Natural (Windows_Request.Negotiate_Context_Offset) =
           SMB.Spec.SMB2.Header_Size + 48
         and then N.Is_Zero (Body_A1, 46, 48)
         and then N.Is_Negotiate_Context
           (Body_A1, 48, N.Preauth_Integrity_Capabilities, 38)
         and then N.Is_Preauth_Integrity_Capabilities
           (N.Context_Data (Body_A1, 48, 38), (0 => N.SHA_512),
            Body_A1 (62 .. 93))
         and then N.Next_Context (48, 38) = 96
         and then N.Is_Zero (Body_A1, 94, 96)
         and then N.Is_Negotiate_Context
           (Body_A1, 96, N.Encryption_Capabilities, 6)
         and then N.Is_Encryption_Capabilities
           (N.Context_Data (Body_A1, 96, 6),
            (N.AES_128_GCM, N.AES_128_CCM))
         and then Body_A1'Length = 96 + 8 + 6,
         "Windows 10's NEGOTIATE, blog appendix A.1");
      Passed;
      pragma Assert
        (Body_A2'Length = 108
         and then N.Is_Negotiate_Request
           (Body_A2, Windows_Request, Body_A2 (12 .. 27),
            Windows_Dialect_List)
         and then N.Is_Negotiate_Context
           (Body_A2, 48, N.Preauth_Integrity_Capabilities, 38)
         and then N.Is_Preauth_Integrity_Capabilities
           (N.Context_Data (Body_A2, 48, 38), (0 => N.SHA_512),
            Body_A2 (62 .. 93))
         and then N.Is_Negotiate_Context
           (Body_A2, 96, N.Encryption_Capabilities, 4)
         and then N.Is_Encryption_Capabilities
           (N.Context_Data (Body_A2, 96, 4), (0 => N.AES_128_CCM))
         and then Body_A2'Length = 96 + 8 + 4
         and then Body_B'Length = 94
         and then N.Is_Negotiate_Request
           (Body_B, (Windows_Request with delta Negotiate_Context_Count => 1),
            Body_B (12 .. 27), Windows_Dialect_List)
         and then N.Is_Negotiate_Context
           (Body_B, 48, N.Preauth_Integrity_Capabilities, 38)
         and then N.Is_Preauth_Integrity_Capabilities
           (N.Context_Data (Body_B, 48, 38), (0 => N.SHA_512),
            Body_B (62 .. 93))
         and then Body_B'Length = 48 + 8 + 38,
         "Windows 10's NEGOTIATE, blog appendices A.2 and B");
      Passed;
      for Index in Body_A1'Range loop
         declare
            Changed : SMB.Bytes := Body_A1;
         begin
            Changed (Index) := Changed (Index) xor 16#01#;
            --  The padding bytes have no value in the standard.
            pragma Assert
              (Index in 46 .. 47 | 94 .. 95
               or else not
                 (N.Is_Negotiate_Request
                    (Changed, Windows_Request, Body_A1 (12 .. 27),
                     Windows_Dialect_List)
                  and then N.Is_Negotiate_Context
                    (Changed, 48, N.Preauth_Integrity_Capabilities, 38)
                  and then N.Is_Preauth_Integrity_Capabilities
                    (N.Context_Data (Changed, 48, 38), (0 => N.SHA_512),
                     Body_A1 (62 .. 93))
                  and then N.Is_Negotiate_Context
                    (Changed, 96, N.Encryption_Capabilities, 6)
                  and then N.Is_Encryption_Capabilities
                    (N.Context_Data (Changed, 96, 6),
                     (N.AES_128_GCM, N.AES_128_CCM))),
               "every byte of Windows 10's NEGOTIATE");
         end;
      end loop;
      Passed;
      --  Without 3.1.1 the 8 bytes are ClientStartTime, which is 0; there
      --  is at least one dialect; and a list of algorithms is never empty.
      declare
         Only_21 : constant SMB.Bytes :=
           Hex ("2400" & "0200" & "0100" & "0000" & "00000000")
           & Guid & Hex ("0000000000000000" & "0202" & "1002");
         Started : SMB.Bytes := Only_21;
         No_Dialect : SMB.Bytes := Only_21 (0 .. 35);
      begin
         Started (30) := 1;
         No_Dialect (2) := 0;
         pragma Assert
           (N.Is_Negotiate_Request
              (Only_21, (2, 1, 0, 0, 0), Guid,
               (N.Dialect_0202, N.Dialect_0210))
            and then not N.Offers_0311 ((N.Dialect_0202, N.Dialect_0210))
            --  NegotiateContextOffset and NegotiateContextCount do not
            --  exist without 3.1.1.
            and then N.Is_Negotiate_Request
              (Only_21, (2, 1, 0, 16#70#, 2), Guid,
               (N.Dialect_0202, N.Dialect_0210))
            and then not N.Is_Negotiate_Request
              (Started, (2, 1, 0, 0, 0), Guid,
               (N.Dialect_0202, N.Dialect_0210))
            and then not N.Is_Negotiate_Request
              (No_Dialect, (0, 1, 0, 0, 0), Guid, (1 .. 0 => 0))
            and then not N.Is_Encryption_Capabilities
              (Hex ("0000"), (1 .. 0 => 0))
            and then not N.Is_Signing_Capabilities
              (Hex ("0000"), (1 .. 0 => 0))
            and then not N.Is_Preauth_Integrity_Capabilities
              (Hex ("00000000"), (1 .. 0 => 0), Hex (""))
            --  A context's data is exactly its fields.
            and then N.Is_Encryption_Capabilities
              (Hex ("01000100"), (0 => N.AES_128_CCM))
            and then not N.Is_Encryption_Capabilities
              (Hex ("0100010000"), (0 => N.AES_128_CCM))
            and then N.Is_Signing_Capabilities
              (Hex ("01000100"), (0 => N.AES_CMAC))
            and then not N.Is_Signing_Capabilities
              (Hex ("0100010000"), (0 => N.AES_CMAC))
            and then N.Is_Preauth_Integrity_Capabilities
              (Hex ("010001000100AB"), (0 => N.SHA_512), Hex ("AB"))
            and then not N.Is_Preauth_Integrity_Capabilities
              (Hex ("010001000100AB00"), (0 => N.SHA_512), Hex ("AB")),
            "ClientStartTime, no empty lists, exact context data");
      end;
      Passed;
      --  Alignment: each context at the first multiple of 8 after the one
      --  before; a context that ends aligned is followed at once.
      pragma Assert
        (N.First_Context (1) = 40 and then N.First_Context (2) = 40
         and then N.First_Context (3) = 48
         and then N.Next_Context (40, 38) = 88
         and then N.Next_Context (88, 10) = 112
         and then N.Next_Context (88, 8) = 104
         and then N.Align_8 (0) = 0 and then N.Align_8 (1) = 8,
         "negotiate context alignment");
      Passed;
      pragma Assert
        (Client_Only_311'Length = 126
         and then N.Is_Client_Negotiate_Request
           (Client_Only_311, Guid, Salt, False)
         and then N.Is_Client_Negotiate_Request
           (Client_With_21, Guid, Salt, True)
         and then N.Is_Client_Negotiate_Request
           (Client_High, Guid, Salt, False)
         and then not N.Is_Client_Negotiate_Request
           (Client_Only_311, Guid, Salt, True)
         and then not N.Is_Client_Negotiate_Request
           (Client_With_21, Guid, Salt, False)
         and then not N.Is_Client_Negotiate_Request
           (Client_Only_311 & Hex ("00"), Guid, Salt, False)
         and then not N.Is_Client_Negotiate_Request
           (Client_Only_311, Guid, Guid & Guid, False),
         "this client's NEGOTIATE");
      Passed;
      for Allow_21 in Boolean loop
         for Index in Client_Only_311'Range loop
            declare
               Changed : SMB.Bytes := Client_Body (Allow_21);
            begin
               Changed (Index) := Changed (Index) xor 16#01#;
               pragma Assert
                 (not N.Is_Client_Negotiate_Request
                    (Changed, Guid, Salt, Allow_21),
                  "every byte of this client's NEGOTIATE");
            end;
         end loop;
      end loop;
      Passed;
      pragma Assert
        (N.Client_Negotiate (False)
         = (Dialect_Count => 1, Security_Mode => 3, Capabilities => 16#44#,
            Negotiate_Context_Offset => 104, Negotiate_Context_Count => 3)
         and then N.Client_Negotiate (True).Dialect_Count = 2
         and then N.Client_Negotiate (True).Negotiate_Context_Offset = 104
         and then N.Client_Ciphers = (2, 1, 4, 3)
         and then N.Client_Signing_Algorithms = (2, 1)
         and then N.Client_Hash_Algorithms = (0 => 1)
         and then N.Preauth_Integrity_Capabilities = 1
         and then N.Encryption_Capabilities = 2
         and then N.Signing_Capabilities = 8
         and then N.Dialect_0311 = 16#0311#
         and then N.Global_Cap_Encryption = 16#40#
         and then N.Global_Cap_Large_MTU = 4,
         "this client's NEGOTIATE fields, and the constants");
      Passed;
   end Test_SMB2_Negotiate;
begin
   Test_Encoding;
   Test_SMB2_Header;
   Test_SMB2_Transfer;
   Test_SMB2_Session;
   Test_SMB2_Create;
   Test_SMB2_Info;
   Test_SMB2_Negotiate;
   Ada.Text_IO.Put_Line
     ("specification tests passed:" & Natural'Image (Checks) & " checks");
end Spec_Test;
