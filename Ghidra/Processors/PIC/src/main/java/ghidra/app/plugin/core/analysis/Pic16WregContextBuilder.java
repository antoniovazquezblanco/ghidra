package ghidra.app.plugin.core.analysis;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

public class Pic16WregContextBuilder extends RegisterContextBuilder {

	Pic16WregContextBuilder(Program program) {
		super(program, program.getRegister("W"), false);
	}

	void processInstruction(Instruction instr) {
		String mnemonic = instr.getMnemonicString();
		
	}
}
