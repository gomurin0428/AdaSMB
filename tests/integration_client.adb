with Test_Dialects;
with Ada.Calendar;
with Ada.Environment_Variables;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Authentication_Test_Support;
with SMB;
with SMB.Client;
with SMB.Core_Auth;
with SMB.Core_Negotiate;
with SMB.Engine;

procedure Integration_Client is
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.Bytes;
   use type SMB.Client.Access_Mode;
   use type SMB.DWord;
   use type SMB.QWord;

   function Env (Name : String) return String is
   begin
      return Ada.Environment_Variables.Value (Name);
   end Env;

   procedure Assert (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Assert;

   Host : constant String := Env ("SMB_TEST_HOST");
   Port : constant Positive := Positive'Value (Env ("SMB_TEST_PORT"));
   Share : constant String := Env ("SMB_TEST_SHARE");
   User : constant String := Env ("SMB_TEST_USER");
   Password : constant String := Env ("SMB_TEST_PASSWORD");
   Unicode_Name : constant String :=
     Character'Val (16#E6#) & Character'Val (16#97#)
     & Character'Val (16#A5#) & Character'Val (16#F0#)
     & Character'Val (16#9F#) & Character'Val (16#98#)
     & Character'Val (16#80#) & ".bin";
   Renamed_Name : constant String := "renamed.bin";

   --  A file's times, as a server keeps them: set, and in a plausible year.
   procedure Check_Times
     (Info : SMB.Client.File_Information; Label : String) is
      type Times is array (1 .. 3) of SMB.QWord;
   begin
      for Value of Times'
        (Info.Creation_Time, Info.Last_Write_Time, Info.Change_Time)
      loop
         Assert
           (Ada.Calendar.Year (SMB.Client.To_Time (Value)) in 2020 .. 2200,
            Label & ": implausible time" & SMB.QWord'Image (Value));
      end loop;
      Assert ((Info.Attributes and 16#10#) = 0,
              Label & ": a file reported as a directory");
   end Check_Times;
begin
   declare
      Wrong : SMB.Client.Connection;
      Rejected : Boolean := False;
   begin
      SMB.Client.Connect (Wrong, Host, Port,
         Dialects => Test_Dialects.Policy);
      begin
         SMB.Client.Authenticate (Wrong, User, "definitely-wrong-password");
      exception
         when others =>
            Rejected := True;
      end;
      SMB.Client.Disconnect (Wrong);
      Assert (Rejected, "wrong-password authentication unexpectedly succeeded");
   end;

   declare
      Client : SMB.Client.Connection;
   begin
      Authentication_Test_Support.Reset_Entropy_Calls;
      SMB.Client.Connect
        (Client, Host, Port,
         Entropy => Authentication_Test_Support.Fail_After_Negotiate'Access,
         Dialects => Test_Dialects.Policy);
      begin
         SMB.Client.Authenticate (Client, User, Password);
         raise Program_Error with "injected authentication unexpectedly succeeded";
      exception
         when SMB.Invalid_State => null;
      end;
      Assert
        (not SMB.Client.Is_Connected (Client),
         "post-challenge authentication exception retained connection");
   end;

   declare
      Client : SMB.Client.Connection;

      procedure Check_Invalid_Credentials is
         procedure Reject (Name, Secret, Domain : String) is
            Original_Status : constant SMB.DWord :=
              SMB.Client.Last_NT_Status (Client);
         begin
            begin
               SMB.Client.Authenticate (Client, Name, Secret, Domain);
               raise Program_Error with "invalid credentials accepted";
            exception
               when SMB.Authentication_Error => null;
            end;
            Assert
              (SMB.Client.Is_Connected (Client),
               "invalid credential preflight disconnected client");
            Assert
              (SMB.Client.Last_NT_Status (Client) = Original_Status,
               "invalid credential preflight changed last NTSTATUS");
         end Reject;
         Invalid_UTF8 : constant String := (1 => Character'Val (16#FF#));
         Too_Long : constant String
           (1 .. SMB.Core_Auth.Maximum_Credential_Bytes + 1) :=
             (others => 'a');
      begin
         Reject ("", Password, "");
         Reject (Invalid_UTF8, Password, "");
         Reject (String'(1 => Character'Val (0)), Password, "");
         Reject (User, Invalid_UTF8, "");
         Reject (User, Password, Invalid_UTF8);
         Reject (Too_Long, Password, "");
         Reject (User, Too_Long, "");
         Reject (User, Password, Too_Long);
      end Check_Invalid_Credentials;

      procedure Check_Invalid_Shares is
         procedure Reject (Name : String) is
            Original_Status : constant SMB.DWord :=
              SMB.Client.Last_NT_Status (Client);
         begin
            begin
               SMB.Client.Connect_Share (Client, Name);
               raise Program_Error with "invalid share name accepted";
            exception
               when SMB.Protocol_Error => null;
            end;
            Assert
              (SMB.Client.Is_Connected (Client),
               "invalid share preflight disconnected client");
            Assert
              (SMB.Client.Last_NT_Status (Client) = Original_Status,
               "invalid share preflight changed last NTSTATUS");
         end Reject;
      begin
         Reject ("");
         Reject ("share/child");
         Reject (String'(1 => Character'Val (16#FF#)));
         Reject (String'(1 .. 256 => 'a'));
      end Check_Invalid_Shares;

      procedure Check_Handle_Capacity (Depth : Positive) is
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);

         procedure Check_Still_Usable is
            Data : constant SMB.Bytes := SMB.Client.Read (Client, File, 0, 1);
         begin
            Assert (SMB.Client.Is_Connected (Client), "capacity error disconnected");
            Assert (Data'Length = 1, "capacity error invalidated an existing handle");
         end Check_Still_Usable;
      begin
         if Depth < SMB.Engine.Maximum_Handles then
            Check_Handle_Capacity (Depth + 1);
         else
            begin
               declare
                  Entries : constant SMB.Client.Directory_Entry_Array :=
                    SMB.Client.List_Directory (Client);
                  pragma Unreferenced (Entries);
               begin
                  raise Program_Error with "directory CREATE exceeded handle limit";
               end;
            exception
               when SMB.Invalid_State => null;
            end;
            Check_Still_Usable;
            begin
               SMB.Client.Rename
                 (Client, "fixture.txt", "capacity-should-not-rename.txt");
               raise Program_Error with "rename CREATE exceeded handle limit";
            exception
               when SMB.Invalid_State => null;
            end;
            Check_Still_Usable;
         end if;
         SMB.Client.Close (Client, File);
      end Check_Handle_Capacity;
   begin
      --  A server without a cipher (2.1, or 3.1.1 with encryption off)
      --  fails Require_Encryption and leaves nothing connected.
      if not Test_Dialects.Encrypted then
         declare
            Refused : SMB.Client.Connection;
         begin
            SMB.Client.Connect (Refused, Host, Port,
               Dialects => Test_Dialects.Policy,
               Require_Encryption => True);
            raise Program_Error with
              "Require_Encryption accepted a server without a cipher";
         exception
            when SMB.Protocol_Error =>
               Assert (not SMB.Client.Is_Connected (Refused),
                       "refused encryption left a connection");
         end;
      end if;
      SMB.Client.Connect (Client, Host, Port,
         Dialects => Test_Dialects.Policy,
         Require_Encryption => Test_Dialects.Required);
      --  The 3.1.1-only run talks to a 3.1.1-only server; the other run's
      --  server speaks only 2.1.
      Assert
        (SMB.Client.Negotiated_Dialect (Client) =
           (if SMB.Client."=" (Test_Dialects.Policy, SMB.Client.SMB_311_Only)
            then SMB.SMB2_Dialect_0311 else SMB.SMB2_Dialect_0210),
         "negotiated dialect");
      Assert (not SMB.Client.Is_Encrypted (Client),
              "encrypted before authentication");
      --  SMB_TEST_CIPHER names the one cipher the server allows.
      Ada.Text_IO.Put_Line
        ("negotiated cipher: "
         & SMB.Core_Negotiate.Cipher_Id'Image
             (SMB.Client.Negotiated_Cipher (Client)));
      if Ada.Environment_Variables.Exists ("SMB_TEST_CIPHER") then
         Assert
           (SMB.Core_Negotiate.Cipher_Id'Image
              (SMB.Client.Negotiated_Cipher (Client)) =
                Env ("SMB_TEST_CIPHER"),
            "negotiated cipher is not " & Env ("SMB_TEST_CIPHER"));
      end if;
      Assert
        (SMB.Core_Negotiate."="
           (SMB.Client.Negotiated_Cipher (Client),
            SMB.Core_Negotiate.No_Cipher) = not Test_Dialects.Encrypted,
         "a cipher exactly when the run encrypts");
      --  SMB_TEST_SIGNING names the signing algorithm the server must have
      --  chosen.
      Ada.Text_IO.Put_Line
        ("negotiated signing: "
         & SMB.Core_Negotiate.Signing_Id'Image
             (SMB.Client.Negotiated_Signing (Client)));
      if Ada.Environment_Variables.Exists ("SMB_TEST_SIGNING") then
         Assert
           (SMB.Core_Negotiate.Signing_Id'Image
              (SMB.Client.Negotiated_Signing (Client)) =
                Env ("SMB_TEST_SIGNING"),
            "negotiated signing is not " & Env ("SMB_TEST_SIGNING"));
      end if;
      Assert
        (SMB.Core_Negotiate."="
           (SMB.Client.Negotiated_Signing (Client),
            SMB.Core_Negotiate.HMAC_SHA256)
         = (SMB.Client.Negotiated_Dialect (Client) /= SMB.SMB2_Dialect_0311),
         "HMAC-SHA256 signing exactly under 2.1");
      Check_Invalid_Credentials;
      SMB.Client.Authenticate (Client, User, Password);
      --  Everything after authentication, the share included, is
      --  encrypted exactly when the server negotiated a cipher, which the
      --  encrypting run requires.
      Assert (SMB.Client.Is_Encrypted (Client) = Test_Dialects.Encrypted,
              "encryption after authentication");
      begin
         SMB.Client.Authenticate (Client, User, Password);
         raise Program_Error with
           "repeat authentication on authenticated connection succeeded";
      exception
         when SMB.Invalid_State =>
            Assert
              (SMB.Client.Is_Connected (Client),
               "initial invalid-state authentication disconnected client");
      end;
      begin
         SMB.Client.Authenticate (Client, "", Password);
         raise Program_Error with
           "invalid credentials bypassed authentication state validation";
      exception
         when SMB.Invalid_State =>
            Assert
              (SMB.Client.Is_Connected (Client),
               "invalid credentials on authenticated connection disconnected");
      end;
      Check_Invalid_Shares;
      SMB.Client.Connect_Share (Client, Share);
      declare
         Fixture : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
         Rejected_Share : Boolean := False;
         procedure Check_Rejected_Path (Path : String) is
            type Path_Operation is
              (Open_Path, List_Path, Make_Path, Remove_Path,
               Remove_Directory_Path, Rename_Source, Rename_Target);
         begin
            for Operation in Path_Operation loop
               declare
                  Original_Status : constant SMB.DWord :=
                    SMB.Client.Last_NT_Status (Client);
               begin
                  begin
                     case Operation is
                        when Open_Path =>
                           declare
                              Unexpected : SMB.Client.Handle :=
                                SMB.Client.Open_File (Client, Path);
                              pragma Unreferenced (Unexpected);
                           begin
                              null;
                           end;
                        when List_Path =>
                           declare
                              Unexpected : constant SMB.Client.Directory_Entry_Array :=
                                SMB.Client.List_Directory (Client, Path);
                              pragma Unreferenced (Unexpected);
                           begin
                              null;
                           end;
                        when Make_Path => SMB.Client.Make_Directory (Client, Path);
                        when Remove_Path => SMB.Client.Remove_File (Client, Path);
                        when Remove_Directory_Path =>
                           SMB.Client.Remove_Directory (Client, Path);
                        when Rename_Source =>
                           SMB.Client.Rename
                             (Client, Path, "preflight-should-not-rename.txt");
                        when Rename_Target =>
                           SMB.Client.Rename (Client, "fixture.txt", Path);
                     end case;
                     raise Program_Error with
                       "invalid path accepted: " & Path_Operation'Image (Operation);
                  exception
                     when SMB.Protocol_Error => null;
                  end;
                  Assert
                    (SMB.Client.Is_Connected (Client),
                     "invalid path disconnected: " & Path_Operation'Image (Operation));
                  Assert
                    (SMB.Client.Last_NT_Status (Client) = Original_Status,
                     "invalid path changed last NTSTATUS");
                  Assert
                    (SMB.Client.Read (Client, Fixture, 0, 1)'Length = 1,
                     "invalid path damaged an existing handle");
               end;
            end loop;
         end Check_Rejected_Path;
      begin
         Check_Invalid_Shares;
         Assert
           (SMB.Client.Read (Client, Fixture, 0, 1)'Length = 1,
            "invalid share preflight invalidated an active share handle");
         Check_Rejected_Path ("../fixture.txt");
         Check_Rejected_Path ("/fixture.txt");
         Check_Rejected_Path ("fixture.txt:stream");
         Check_Rejected_Path (String'(1 => Character'Val (16#FF#)));
         Check_Rejected_Path (Character'Val (16#E2#) & Character'Val (16#82#));
         Check_Rejected_Path (String'(1 .. 32_768 => 'a'));
         begin
            SMB.Client.Connect_Share (Client, Share);
         exception
            when SMB.Invalid_State =>
               Rejected_Share := True;
         end;
         Assert
           (Rejected_Share,
            "repeat Connect_Share on an active share was not rejected");
         Assert
           (SMB.Client.Read (Client, Fixture, 0, 1)'Length = 1,
            "repeat Connect_Share invalidated the active share handle");
         SMB.Client.Close (Client, Fixture);
      end;
      Check_Handle_Capacity (1);

      begin
         declare
            Missing : SMB.Client.Handle :=
              SMB.Client.Open_File
                (Client, "missing-file-for-adasmb", SMB.Client.Read_Only);
         begin
            SMB.Client.Close (Client, Missing);
            raise Program_Error with "missing file unexpectedly opened";
         end;
      exception
         when SMB.NT_Status_Error =>
            Assert
              (SMB.Client.Last_NT_Status (Client) =
                 SMB.Status_Object_Name_Not_Found,
               "missing-file NTSTATUS was not preserved");
      end;

      begin
         declare
            Denied : SMB.Client.Handle :=
              SMB.Client.Open_File
                (Client, "readonly.txt", SMB.Client.Write_Only);
         begin
            SMB.Client.Close (Client, Denied);
            raise Program_Error with "read-only file unexpectedly opened for write";
         end;
      exception
         when SMB.NT_Status_Error =>
            Assert
              (SMB.Client.Last_NT_Status (Client) = SMB.Status_Access_Denied,
               "access-denied NTSTATUS was not preserved");
      end;

      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, Unicode_Name, SMB.Client.Read_Write,
              SMB.Client.Create_New);
         Data : SMB.Bytes (0 .. 70_000);

         procedure Check_Local_Transfer_Errors is
            type Rejected_Transfer is
              (Oversized_Read, Oversized_Write, Overflowing_Read,
               Overflowing_Write, Read_Write_Only, Write_Read_Only);
            Reader : SMB.Client.Handle :=
              SMB.Client.Open_File (Client, Unicode_Name, SMB.Client.Read_Only);
            Writer : SMB.Client.Handle :=
              SMB.Client.Open_File (Client, Unicode_Name, SMB.Client.Write_Only);

            procedure Reject_Read
              (Source : SMB.Client.Handle;
               Offset : SMB.QWord;
               Length : Positive) is
               Unexpected : constant SMB.Bytes :=
                 SMB.Client.Read (Client, Source, Offset, Length);
            begin
               raise Program_Error with
                 "invalid READ returned" & Natural'Image (Unexpected'Length)
                 & " bytes";
            end Reject_Read;
         begin
            for Kind in Rejected_Transfer loop
               begin
                  declare
                     Missing : SMB.Client.Handle :=
                       SMB.Client.Open_File
                         (Client, "missing-file-for-adasmb",
                          SMB.Client.Read_Only);
                  begin
                     SMB.Client.Close (Client, Missing);
                     raise Program_Error with "transfer error fixture exists";
                  end;
               exception
                  when SMB.NT_Status_Error =>
                     Assert
                       (SMB.Client.Last_NT_Status (Client) =
                          SMB.Status_Object_Name_Not_Found,
                        "transfer error test did not seed a nonzero NTSTATUS");
               end;
               declare
                  Original_Status : constant SMB.DWord :=
                    SMB.Client.Last_NT_Status (Client);
               begin
                  begin
                     case Kind is
                        when Oversized_Read =>
                           Reject_Read
                             (File, 0, SMB.Maximum_Frame_Size + 1);
                        when Oversized_Write =>
                           declare
                              Excess : constant SMB.Bytes
                                (0 .. SMB.Maximum_Frame_Size) :=
                                  (others => 16#A5#);
                           begin
                              SMB.Client.Write (Client, File, 0, Excess);
                           end;
                        when Overflowing_Read =>
                           Reject_Read (File, SMB.QWord'Last, 1);
                        when Overflowing_Write =>
                           SMB.Client.Write
                             (Client, File, SMB.QWord'Last, Data (0 .. 0));
                        when Read_Write_Only =>
                           Reject_Read (Writer, 0, 1);
                        when Write_Read_Only =>
                           SMB.Client.Write (Client, Reader, 0, Data (0 .. 0));
                     end case;
                     raise Program_Error with
                       "invalid transfer accepted: "
                       & Rejected_Transfer'Image (Kind);
                  exception
                     when SMB.Protocol_Error =>
                        Assert
                          (Kind in Oversized_Read .. Overflowing_Write,
                           "wrong transfer error kind: "
                           & Rejected_Transfer'Image (Kind));
                     when SMB.Invalid_State =>
                        Assert
                          (Kind in Read_Write_Only | Write_Read_Only,
                           "wrong transfer error kind: "
                           & Rejected_Transfer'Image (Kind));
                  end;
                  Assert
                    (SMB.Client.Is_Connected (Client),
                     "local transfer error disconnected client: "
                     & Rejected_Transfer'Image (Kind));
                  Assert
                    (SMB.Client.Last_NT_Status (Client) = Original_Status,
                     "local transfer error changed last NTSTATUS: "
                     & Rejected_Transfer'Image (Kind));
               end;
               SMB.Client.Write (Client, Writer, 0, Data (0 .. 0));
               Assert
                 (SMB.Client.Read (Client, Reader, 0, 1) = Data (0 .. 0)
                  and then SMB.Client.Read (Client, File, 0, 1) = Data (0 .. 0),
                  "local transfer error invalidated an existing handle: "
                  & Rejected_Transfer'Image (Kind));
            end loop;
            SMB.Client.Close (Client, Writer);
            SMB.Client.Close (Client, Reader);
         end Check_Local_Transfer_Errors;
      begin
         for I in Data'Range loop
            Data (I) := SMB.Byte (I mod 251);
         end loop;
         SMB.Client.Write (Client, File, 0, Data);
         declare
            Read_Back : constant SMB.Bytes :=
              SMB.Client.Read (Client, File, 0, Data'Length);
         begin
            Assert (Read_Back'Length = Data'Length, "short large-file read");
            for I in Data'Range loop
               Assert (Read_Back (Read_Back'First + I) = Data (I),
                       "large-file data mismatch");
            end loop;
         end;
         Check_Local_Transfer_Errors;
         declare
            Info : constant SMB.Client.File_Information :=
              SMB.Client.Query_Information (Client, File);
            Writer : SMB.Client.Handle :=
              SMB.Client.Open_File
                (Client, Unicode_Name, SMB.Client.Write_Only);
            Through_Writer : constant SMB.Client.File_Information :=
              SMB.Client.Query_Information (Client, Writer);
         begin
            SMB.Client.Close (Client, Writer);
            Assert (Info.Size = SMB.QWord (Data'Length),
                    "QUERY_INFO size after a write:"
                    & SMB.QWord'Image (Info.Size));
            Assert (Through_Writer.Size = Info.Size
                    and then Through_Writer.Creation_Time = Info.Creation_Time,
                    "QUERY_INFO through a write-only handle differs");
            Check_Times (Info, "written file");
         end;
         declare
            Partial_EOF : constant SMB.Bytes :=
              SMB.Client.Read
                (Client, File, SMB.QWord (Data'Length - 1), 10);
            Beyond_EOF : constant SMB.Bytes :=
              SMB.Client.Read (Client, File, SMB.QWord (Data'Length), 10);
         begin
            Assert (Partial_EOF'Length = 1, "partial read at EOF was lost");
            Assert (Partial_EOF (Partial_EOF'First) = Data (Data'Last),
                    "partial EOF byte mismatch");
            Assert (Beyond_EOF'Length = 0, "read beyond EOF was not empty");
         end;
         declare
            Other : SMB.Client.Connection;
            Foreign_Rejected : Boolean := False;
         begin
            SMB.Client.Connect (Other, Host, Port,
         Dialects => Test_Dialects.Policy);
            SMB.Client.Authenticate (Other, User, Password);
            SMB.Client.Connect_Share (Other, Share);
            begin
               declare
                  Ignored : constant SMB.Bytes := SMB.Client.Read (Other, File, 0, 1);
               begin
                  Assert (Ignored'Length = 0, "foreign handle unexpectedly read");
               end;
            exception
               when SMB.Invalid_State =>
                  Foreign_Rejected := True;
            end;
            Assert (Foreign_Rejected, "foreign handle was accepted");
            SMB.Client.Disconnect (Other);
         end;
         --  Truncate, then extend: the extension reads back as zeros.
         SMB.Client.Set_Size (Client, File, 1_000);
         declare
            Kept : constant SMB.Bytes := SMB.Client.Read (Client, File, 0, 2_000);
         begin
            Assert (SMB.Client.Query_Information (Client, File).Size = 1_000
                    and then Kept'Length = 1_000
                    and then Kept = Data (0 .. 999),
                    "truncation to 1,000 bytes");
         end;
         --  The extension goes through a write-only handle.
         declare
            Writer : SMB.Client.Handle :=
              SMB.Client.Open_File
                (Client, Unicode_Name, SMB.Client.Write_Only);
         begin
            SMB.Client.Set_Size (Client, Writer, 5_000);
            SMB.Client.Close (Client, Writer);
         end;
         declare
            Grown : constant SMB.Bytes := SMB.Client.Read (Client, File, 0, 6_000);
         begin
            Assert (SMB.Client.Query_Information (Client, File).Size = 5_000
                    and then Grown'Length = 5_000
                    and then Grown (Grown'First .. Grown'First + 999) =
                      Data (0 .. 999)
                    and then Grown (Grown'First + 1_000 .. Grown'Last) =
                      (Grown'First + 1_000 .. Grown'Last => 0),
                    "extension to 5,000 bytes");
         end;
         declare
            Reader : SMB.Client.Handle :=
              SMB.Client.Open_File (Client, Unicode_Name, SMB.Client.Read_Only);
            Refused : Boolean := False;
         begin
            begin
               SMB.Client.Set_Size (Client, Reader, 0);
            exception
               when SMB.Invalid_State =>
                  Refused := True;
            end;
            Assert (Refused and then SMB.Client.Is_Connected (Client)
                    and then SMB.Client.Last_NT_Status (Client) = SMB.Success,
                    "resize through a read-only handle was not refused locally");
            Refused := False;
            begin
               SMB.Client.Set_Size (Client, File, 2 ** 63);
            exception
               when SMB.Protocol_Error =>
                  Refused := True;
            end;
            Assert (Refused and then SMB.Client.Is_Connected (Client)
                    and then SMB.Client.Last_NT_Status (Client) = SMB.Success
                    and then SMB.Client.Query_Information (Client, File).Size =
                      5_000,
                    "a size of 2**63 was not refused locally");
            SMB.Client.Close (Client, Reader);
         end;
         SMB.Client.Close (Client, File);
         begin
            declare
               Ignored : constant SMB.Bytes := SMB.Client.Read (Client, File, 0, 1);
            begin
               Assert (Ignored'Length = 0, "stale handle unexpectedly read");
            end;
            raise Program_Error with "stale handle was accepted";
         exception
            when SMB.Invalid_State => null;
         end;
         begin
            declare
               Ignored : constant SMB.Client.File_Information :=
                 SMB.Client.Query_Information (Client, File);
            begin
               Assert (Ignored.Size = 0, "stale handle unexpectedly queried");
            end;
            raise Program_Error with "stale handle was queried";
         exception
            when SMB.Invalid_State => null;
         end;
         Assert (SMB.Client.Is_Connected (Client),
                 "a stale-handle query disconnected");
      end;

      SMB.Client.Rename (Client, Unicode_Name, Renamed_Name);
      SMB.Client.Remove_File (Client, Renamed_Name);
      SMB.Client.Make_Directory (Client, "adasmb-empty-directory");
      SMB.Client.Remove_Directory (Client, "adasmb-empty-directory");
      SMB.Client.Make_Directory (Client, "adasmb-nonempty-directory");
      declare
         Child : SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, "adasmb-nonempty-directory/child",
              SMB.Client.Read_Write, SMB.Client.Create_New);
         One_Byte : constant SMB.Bytes (0 .. 0) := (0 => 1);
         Failed : Boolean := False;
      begin
         SMB.Client.Write (Client, Child, 0, One_Byte);
         SMB.Client.Close (Client, Child);
         begin
            SMB.Client.Remove_Directory (Client, "adasmb-nonempty-directory");
         exception
            when SMB.NT_Status_Error =>
               Failed := True;
         end;
         Assert (Failed, "nonempty directory removal unexpectedly succeeded");
         declare
            Usable : SMB.Client.Handle :=
              SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
         begin
            SMB.Client.Close (Client, Usable);
         end;
         SMB.Client.Remove_File
           (Client, "adasmb-nonempty-directory/child");
         SMB.Client.Remove_Directory (Client, "adasmb-nonempty-directory");
      end;
      declare
         Entries : constant SMB.Client.Directory_Entry_Array :=
           SMB.Client.List_Directory (Client);
         Found_Fixture : Boolean := False;
         Found_Readonly : Boolean := False;
         Found_Interrupted_Read : Boolean := False;
      begin
         Assert (Entries'Length = 1_203, "directory membership count mismatch");
         for Item of Entries loop
            declare
               Name : constant String :=
                 Ada.Strings.Unbounded.To_String (Item.Name);
            begin
               if Name = "fixture.txt" then
                  Found_Fixture := True;
                  declare
                     Fixture : SMB.Client.Handle :=
                       SMB.Client.Open_File
                         (Client, Name, SMB.Client.Read_Only);
                     Info : constant SMB.Client.File_Information :=
                       SMB.Client.Query_Information (Client, Fixture);
                  begin
                     SMB.Client.Close (Client, Fixture);
                     Assert (Item.Size = 27 and then Info.Size = 27,
                             "fixture size in the listing or QUERY_INFO");
                     Assert
                       (Item.Creation_Time = Info.Creation_Time
                        and then Item.Last_Write_Time = Info.Last_Write_Time
                        and then Item.Change_Time = Info.Change_Time
                        and then Item.Attributes = Info.Attributes,
                        "listing and QUERY_INFO disagree on the fixture");
                     Check_Times (Info, "fixture");
                  end;
               elsif Name = "readonly.txt" then
                  Found_Readonly := True;
               elsif Name = "interrupted-read.bin" then
                  Found_Interrupted_Read := True;
               elsif Name'Length = 19
                 and then Name (1 .. 11) = "pagination-"
                 and then Name (12 .. 15) >= "0000"
                 and then Name (12 .. 15) <= "9999"
                 and then Name (16 .. 19) = ".txt"
               then
                  null;
               else
                  raise Program_Error with "unexpected directory member: " & Name;
               end if;
            end;
         end loop;
         Assert
           (Found_Fixture and Found_Readonly and Found_Interrupted_Read,
                 "required directory members are missing");
      end;
      declare
         Stale_After_Reconnect : constant SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
      SMB.Client.Disconnect (Client);

      SMB.Client.Connect (Client, Host, Port,
         Dialects => Test_Dialects.Policy);
      SMB.Client.Authenticate (Client, User, Password);
      SMB.Client.Connect_Share (Client, Share);
         declare
            Rejected : Boolean := False;
         begin
            begin
               declare
                  Ignored : constant SMB.Bytes :=
                    SMB.Client.Read (Client, Stale_After_Reconnect, 0, 1);
               begin
                  Assert (Ignored'Length = 0, "reconnected stale handle read");
               end;
            exception
               when SMB.Invalid_State =>
                  Rejected := True;
            end;
            Assert (Rejected, "stale handle survived reconnect");
         end;
      SMB.Client.Disconnect (Client);
      end;
   end;
   Ada.Text_IO.Put_Line ("AdaSMB integration client passed");
end Integration_Client;
