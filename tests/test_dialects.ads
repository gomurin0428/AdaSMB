with SMB.Client;

--  The dialect policy of the integration clients: SMB_311_Only when
--  SMB_TEST_DIALECTS is "311", for the 3.1.1-only Samba run, and
--  SMB_311_Or_21 otherwise, for the 2.1 Samba that the proxy tests use.
package Test_Dialects is
   function Policy return SMB.Client.Dialect_Policy;
end Test_Dialects;
