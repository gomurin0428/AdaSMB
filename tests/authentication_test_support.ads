with SMB;

package Authentication_Test_Support is
   procedure Reset_Entropy_Calls;
   procedure Fail_After_Negotiate (Output : out SMB.Bytes);
end Authentication_Test_Support;
