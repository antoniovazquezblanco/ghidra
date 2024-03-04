package ghidra.app.plugin.core.analysis;

import java.util.HashSet;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Pic16InstructionAnalyzer extends AbstractAnalyzer {

	private static final int INSTRUCTION_LENGTH = 2;

	private static final String COULD_NOT_PROCESS_JUMP_OR_CALL_INSTRUCTION = "Could not process jump or call instruction";

	private static final HashSet<String> CALL_BRANCH_INSTRUCTIONS = new HashSet<String>();
	static {
		CALL_BRANCH_INSTRUCTIONS.add("CALL");
		CALL_BRANCH_INSTRUCTIONS.add("GOTO");
	}

	private Listing mListing;
	private ReferenceManager mRefMgr;
	private BookmarkManager mBookmarkManager;

	private Pic16WregContextBuilder mWregContext;
	private Pic16PclathContextBuilder mPclathContext;

	private AddressSet mNewDisassemblyPoints;

	public Pic16InstructionAnalyzer() {
		super("PIC16 Instruction Analyzer", "Analyzes PIC16 instructions.", AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		mListing = program.getListing();
		mRefMgr = program.getReferenceManager();
		mBookmarkManager = program.getBookmarkManager();

		mWregContext = new Pic16WregContextBuilder(program);
		mPclathContext = new Pic16PclathContextBuilder(program);

		mNewDisassemblyPoints = new AddressSet();

		// Iterate the newly found instructions...
		InstructionIterator instIter = mListing.getInstructions(set, true);
		while (!monitor.isCancelled() && instIter.hasNext()) {
			Instruction instr = instIter.next();
			// First try to update register values...
			mWregContext.processInstruction(instr);
			mPclathContext.processInstruction(instr);
			handleCallOrBranch(instr);
		}

		if (!mNewDisassemblyPoints.isEmpty()) {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.disassemble(mNewDisassemblyPoints);
		}

		return true;
	}

	private void handleCallOrBranch(Instruction instr) {
		FlowType flowType = instr.getFlowType();
		if (!flowType.isJump() && !flowType.isCall())
			return;
		Address destAddr = getImmCallOrBranchDestAddr(instr);
		if (destAddr == null)
			return;
		// Register the memory reference...
		RefType refType = instr.getFlowType().isCall() ? RefType.UNCONDITIONAL_CALL : RefType.UNCONDITIONAL_JUMP;
		mRefMgr.addMemoryReference(instr.getMinAddress(), destAddr, refType, SourceType.DEFAULT, 0);
		// Look for more code on destination address...
		disassembleAt(destAddr);
	}

	private Address getImmCallOrBranchDestAddr(Instruction instr) {
		FlowType flowType = instr.getFlowType();
		if (!flowType.isJump() && !flowType.isCall())
			return null;
		if (!CALL_BRANCH_INSTRUCTIONS.contains(instr.getMnemonicString())) {
			mBookmarkManager.setBookmark(instr.getAddress(), BookmarkType.WARNING,
					COULD_NOT_PROCESS_JUMP_OR_CALL_INSTRUCTION,
					String.format("Unsupported OPCODE %s...", instr.getMnemonicString()));
			return null;
		}
		// Get the OP parameter...
		Object[] objs = instr.getOpObjects(0);
		if (objs.length != 1 || !(objs[0] instanceof Scalar))
			return null;
		// Get parameter value...
		Scalar s = (Scalar) objs[0];
		// Calculate destination address...
		Long pclathValue = mPclathContext.getValueAt(instr);
		if (pclathValue == null) {
			mBookmarkManager.setBookmark(instr.getAddress(), BookmarkType.WARNING,
					COULD_NOT_PROCESS_JUMP_OR_CALL_INSTRUCTION,
					"Could not obtain PCLATH value for address calculation...");
			return null;
		}
		long pclathOffset = ((mPclathContext.getValueAt(instr) & 0b1111000) >> 3) << 11;
		long offset = (pclathOffset + s.getUnsignedValue()) * INSTRUCTION_LENGTH;
		Address destAddr = instr.getMinAddress().getNewAddress(offset);
		return destAddr;
	}

	private void disassembleAt(Address addr) {
		if (mListing.getInstructionAt(addr) != null)
			return;
		mNewDisassemblyPoints.addRange(addr, addr);
	}
}
