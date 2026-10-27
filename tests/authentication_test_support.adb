with SMB.Entropy;

package body Authentication_Test_Support is
   Entropy_Calls : Natural := 0;
   Failure_Call : Positive := 2;
   Failure : Failure_Kind := State_Failure;

   procedure Configure (On_Call : Positive; Kind : Failure_Kind) is
   begin
      Entropy_Calls := 0;
      Failure_Call := On_Call;
      Failure := Kind;
   end Configure;

   function Calls return Natural is (Entropy_Calls);

   procedure Reset_Entropy_Calls is
   begin
      Configure (2, State_Failure);
   end Reset_Entropy_Calls;

   procedure Generate (Output : out SMB.Bytes) is
   begin
      Entropy_Calls := Entropy_Calls + 1;
      if Entropy_Calls = Failure_Call then
         for I in 1 .. Output'Length / 2 loop
            Output (Output'First + (I - 1)) := 16#A5#;
         end loop;
         case Failure is
            when Authentication_Failure =>
               raise SMB.Authentication_Error with "injected entropy failure";
            when State_Failure =>
               raise SMB.Invalid_State with "injected entropy failure";
            when Unexpected_Failure =>
               raise Program_Error with "injected entropy failure";
         end case;
      end if;
      SMB.Entropy.Generate (Output);
   end Generate;
end Authentication_Test_Support;
