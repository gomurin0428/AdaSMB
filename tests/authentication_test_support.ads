with SMB;

package Authentication_Test_Support is
   type Failure_Kind is (Authentication_Failure, State_Failure, Unexpected_Failure);
   procedure Configure (On_Call : Positive; Kind : Failure_Kind);
   function Calls return Natural;
   procedure Reset_Entropy_Calls;
   procedure Generate (Output : out SMB.Bytes);
   procedure Fail_After_Negotiate (Output : out SMB.Bytes) renames Generate;
end Authentication_Test_Support;
