with SMB.Client;

--  The dialect policy of the integration clients: SMB_311_Only when
--  SMB_TEST_DIALECTS is "311", for the 3.1.1-only Samba run, and
--  SMB_311_Or_21 otherwise, for the 2.1 Samba that the proxy tests use.
--  Encrypted is True when SMB_TEST_ENCRYPTION is "on": the 3.1.1 Samba run
--  that requires encryption, where the integration client also passes
--  Require_Encryption and checks that the session is encrypted.
package Test_Dialects is
   function Policy return SMB.Client.Dialect_Policy;
   function Encrypted return Boolean;
end Test_Dialects;
