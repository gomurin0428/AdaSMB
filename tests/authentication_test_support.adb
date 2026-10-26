package body Authentication_Test_Support is
   Entropy_Calls : Natural := 0;

   procedure Reset_Entropy_Calls is
   begin
      Entropy_Calls := 0;
   end Reset_Entropy_Calls;

   procedure Fail_After_Negotiate (Output : out SMB.Bytes) is
   begin
      Entropy_Calls := Entropy_Calls + 1;
      if Entropy_Calls = 1 then
         for Index in Output'Range loop
            Output (Index) := 0;
         end loop;
      else
         raise SMB.Authentication_Error with
           "injected entropy failure after challenge";
      end if;
   end Fail_After_Negotiate;
end Authentication_Test_Support;
