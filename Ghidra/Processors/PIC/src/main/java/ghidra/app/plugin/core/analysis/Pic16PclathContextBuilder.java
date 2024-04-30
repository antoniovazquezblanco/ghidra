/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.HashSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.scalar.Scalar;

public class Pic16PclathContextBuilder extends RegisterContextBuilder {

	private static final int INSTRUCTION_LENGTH = 2;

	private static final long RESET_VECTOR_OFFSET = 0;
	private static final long INTERRUPT_VECTOR_OFFSET = 0x8;

	private static final String COULD_NOT_RECOVER_PCLATH_VALUE = "Could not recover PCLATH value";

	private static final HashSet<String> SKIP_INSTRUCTIONS = new HashSet<String>();
	static {
		SKIP_INSTRUCTIONS.add("DECFSZ");
		SKIP_INSTRUCTIONS.add("INCFSZ");
		SKIP_INSTRUCTIONS.add("BTFSC");
		SKIP_INSTRUCTIONS.add("BTFSS");
	}

	private Program program;
	private ProgramContext programContext;
	private Register reg;
	private BookmarkManager bookmarkManager;

	/**
	 * Track the PCLATH register value in a PIC16 program.
	 * 
	 * @param program information to track the register across.
	 */
	Pic16PclathContextBuilder(Program program) {
		super(program, program.getRegister("PCLATH"), false);
		this.program = program;
		this.programContext = program.getProgramContext();
		this.reg = program.getRegister("PCLATH");
		this.bookmarkManager = program.getBookmarkManager();
	}

	void processInstruction(Instruction instr) {
		// Already got it, no need to process it again...
		Long val = getValueAt(instr);
		if (val != null)
			return;

		// At reset or interrupt PCLATH is 0...
		Address instrAddr = instr.getMinAddress();
		long instrOffset = instrAddr.getOffset();
		if (instrOffset == RESET_VECTOR_OFFSET || instrOffset == INTERRUPT_VECTOR_OFFSET) {
			setValueAt(instr, 0, true);
			writeValue(instr.getMaxAddress());
			return;
		}

		// Check for known instructions that modify PCLATH
		String mnemonic = instr.getMnemonicString();
		if (mnemonic.equals("MOVLP")) {
			// MOVLP #imm
			Scalar s = instr.getScalar(0);
			if (s == null) {
				bookmarkManager.setBookmark(instr.getAddress(), BookmarkType.WARNING, COULD_NOT_RECOVER_PCLATH_VALUE,
						"Could not recover instruction immediate parameter value");
				return;
			}
			long value = s.getUnsignedValue();
			setValueAt(instr, value, true);
			writeValue(instr.getMaxAddress());
			return;
		} else if (mnemonic.equals("MOVWF") && instr.getDefaultOperandRepresentation(0).equals("PCLATH")) {
			// MOVWF PCLATH
			BigInteger wval = program.getProgramContext().getValue(program.getRegister("WREG"), instr.getMinAddress(),
					false);
			if (wval == null) {
				bookmarkManager.setBookmark(instr.getAddress(), BookmarkType.WARNING, COULD_NOT_RECOVER_PCLATH_VALUE,
						"Could not recover WREG value to set PCLATH value!");
				return;
			}
			setValueAt(instr, wval, true);
			writeValue(instr.getMaxAddress());
			return;
		}

		// In any other case try to get a value from the previous instructions
		// If we have reached this point via fall through, the value is preserved...
		Instruction fallFromInstr = getFallFrom(instr);
		if (fallFromInstr != null) {
			// Carry unknown values down if possible
			setValueAt(instr, fallFromInstr.getMinAddress(), true);
			writeValue(instr.getMaxAddress());
			return;
		}

		// If previous instruction was not fall-through, it was maybe a conditional
		// skip...
		Instruction skipFromInstr = getSkipFrom(instr);
		if (skipFromInstr != null) {
			setValueAt(instr, skipFromInstr.getMinAddress(), true);
			writeValue(instr.getMaxAddress());
			return;
		}

		// In any other case assume we got here with CALL or GOTO using PCLATH
		setValueAt(instr, (instrOffset / INSTRUCTION_LENGTH) >> 8, true);
		writeValue(instr.getMaxAddress());
	}

	Long getValueAt(Instruction instr) {
		RegisterValue regVal = programContext.getNonDefaultValue(reg, instr.getMinAddress());
		if (regVal == null)
			return null;
		BigInteger val = regVal.getUnsignedValue();
		if (val == null)
			return null;
		return val.longValue();
	}

	private Instruction getFallFrom(Instruction instr) {
		if (instr == null)
			return null;
		Address fallFromAddr = instr.getFallFrom();
		if (fallFromAddr == null)
			return null;
		return program.getListing().getInstructionAt(fallFromAddr);
	}

	private Instruction getSkipFrom(Instruction instr) {
		if (instr == null)
			return null;
		Address instrAddr = instr.getMinAddress();
		Address skipFromAddr = instrAddr.subtract(2 * INSTRUCTION_LENGTH);
		if (skipFromAddr == null)
			return null;
		Instruction skipFromInstr = program.getListing().getInstructionAt(skipFromAddr);
		if (skipFromInstr == null)
			return null;
		String mnemonic = skipFromInstr.getMnemonicString();
		if (SKIP_INSTRUCTIONS.contains(mnemonic))
			return skipFromInstr;
		return null;
	}
}
