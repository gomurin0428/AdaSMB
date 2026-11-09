with SMB.Client;

--  The dialect policy of the integration clients: SMB_311_Only when
--  SMB_TEST_DIALECTS is "311", for the 3.1.1-only Samba run, and
--  SMB_311_Or_21 otherwise, for the 2.1 Samba that the proxy tests use.
--  SMB_TEST_ENCRYPTION is "on" for a 3.1.1 Samba run that negotiates a
--  cipher, and "required" for one that also requires encryption, where the
--  integration client passes Require_Encryption. Encrypted is True for
--  both: the client then encrypts everything after authentication.
package Test_Dialects is
   function Policy return SMB.Client.Dialect_Policy;
   function Encrypted return Boolean;
   function Required return Boolean;
end Test_Dialects;
