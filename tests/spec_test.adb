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
begin
   Test_Encoding;
   Test_SMB2_Header;
   Ada.Text_IO.Put_Line
     ("specification tests passed:" & Natural'Image (Checks) & " checks");
end Spec_Test;
