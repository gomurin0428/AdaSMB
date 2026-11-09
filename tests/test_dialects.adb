with Ada.Environment_Variables;

package body Test_Dialects is
   function Policy return SMB.Client.Dialect_Policy is
     (if Ada.Environment_Variables.Exists ("SMB_TEST_DIALECTS")
        and then Ada.Environment_Variables.Value ("SMB_TEST_DIALECTS") = "311"
      then SMB.Client.SMB_311_Only
      else SMB.Client.SMB_311_Or_21);

   function Encrypted return Boolean is
     (Ada.Environment_Variables.Exists ("SMB_TEST_ENCRYPTION")
      and then Ada.Environment_Variables.Value ("SMB_TEST_ENCRYPTION") = "on");
end Test_Dialects;
