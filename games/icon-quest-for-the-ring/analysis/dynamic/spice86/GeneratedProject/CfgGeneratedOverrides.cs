using Spice86.Core.CLI;
using Spice86.Core.Emulator.CPU.Exceptions;
using Spice86.Core.Emulator.Function;
using Spice86.Core.Emulator.ReverseEngineer;
using Spice86.Core.Emulator.VM;
using Spice86.Shared.Emulator.Memory;
using Spice86.Shared.Interfaces;
using System;
using System.Collections.Generic;

namespace Spice86.Generated;

public sealed class CfgGeneratedOverrideSupplier : IOverrideSupplier {
    public IDictionary<SegmentedAddress, FunctionInformation> GenerateFunctionInformations(ILoggerService loggerService, Configuration configuration, ushort programStartAddress, Machine machine) {
        return new CfgGeneratedOverrides(new Dictionary<SegmentedAddress, FunctionInformation>(), machine, loggerService, configuration, programStartAddress).FunctionInformations;
    }
}

public class CfgGeneratedOverrides : CSharpOverrideHelper {
    protected readonly ushort cs1;
    protected readonly ushort cs2;

    public CfgGeneratedOverrides(IDictionary<SegmentedAddress, FunctionInformation> functionInformations, Machine machine, ILoggerService loggerService, Configuration configuration, ushort programStartSegment) : base(functionInformations, machine, loggerService, configuration) {
        cs1 = 0x017D;
        cs2 = 0xF000;

        DefineFunction(cs1, 0x0000, entry_017D_0000_017D0);
        DefineFunction(cs1, 0x652B, unknown_017D_652B_07CFB);
        DefineFunction(cs1, 0x655B, unknown_017D_655B_07D2B);
        DefineFunction(cs2, 0x0006, provided_interrupt_handler_8_F000_0006_F0006);
        DefineFunction(cs2, 0x0011, provided_interrupt_handler_9_F000_0011_F0011);
        DefineFunction(cs2, 0x0057, provided_interrupt_handler_70_F000_0057_F0057);
        DefineFunction(cs2, 0x005D, provided_interrupt_handler_74_F000_005D_F005D);
        DefineFunction(cs2, 0x0067, provided_interrupt_handler_B_F000_0067_F0067);
        DefineFunction(cs2, 0x006C, provided_interrupt_handler_C_F000_006C_F006C);
        DefineFunction(cs2, 0x0071, provided_interrupt_handler_D_F000_0071_F0071);
        DefineFunction(cs2, 0x0076, provided_interrupt_handler_F_F000_0076_F0076);
        DefineFunction(cs2, 0x007B, provided_interrupt_handler_72_F000_007B_F007B);
        DefineFunction(cs2, 0x0080, provided_interrupt_handler_73_F000_0080_F0080);
        DefineFunction(cs2, 0x00E2, unknown_F000_00E2_F00E2);
        DefineFunction(cs2, 0x00E3, provided_mouse_driver_F000_00E3_F00E3);
    }

    public virtual Action entry_017D_0000_017D0(int loadOffset) {
    label_017D_0000_017D0_56:
        CheckExternalEvents(cs1, 0x0000);
        // 017D:0000 call near 0x652B
        NearCall(cs1, 0x0003, unknown_017D_652B_07CFB);
        throw FailAsUntested("Call at 017D:0000 returned to 017D:0003, but no continuation was observed during discovery.");
    }

    public virtual Action unknown_017D_652B_07CFB(int loadOffset) {
    label_017D_652B_07CFB_57:
        CheckExternalEvents(cs1, 0x652B);
        VerifySpeculativeEntryOrFail(cs1, 0x652B, [(byte)0x8C, (byte)0xC8]);
        // 017D:652B mov AX,CS
        AX = CS;
        VerifySpeculativeEntryOrFail(cs1, 0x652D, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x03, (byte)0x00]);
        // 017D:652D add AX,word ptr CS:[3]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0003]);
        VerifySpeculativeEntryOrFail(cs1, 0x6532, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x05, (byte)0x00]);
        // 017D:6532 add AX,word ptr CS:[5]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0005]);
        VerifySpeculativeEntryOrFail(cs1, 0x6537, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x07, (byte)0x00]);
        // 017D:6537 add AX,word ptr CS:[7]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0007]);
        VerifySpeculativeEntryOrFail(cs1, 0x653C, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x09, (byte)0x00]);
        // 017D:653C add AX,word ptr CS:[9]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0009]);
        VerifySpeculativeEntryOrFail(cs1, 0x6541, [(byte)0x3B, (byte)0x06, (byte)0x02, (byte)0x00]);
        // 017D:6541 cmp AX,word ptr DS:[2]
        Alu16.Sub(AX, UInt16[DS, (ushort)0x0002]);
        VerifySpeculativeEntryOrFail(cs1, 0x6545, [(byte)0x76, (byte)0x21]);
        // 017D:6545 jbe short 0x6568
        if (CarryFlag || ZeroFlag) {
            goto label_017D_6568_07D38_66;
        }
    label_017D_6547_07D17_68:
        CheckExternalEvents(cs1, 0x6547);
        VerifySpeculativeEntryOrFail(cs1, 0x6547, [(byte)0x1E]);
        // 017D:6547 push DS
        Stack.Push16(DS);
        VerifySpeculativeEntryOrFail(cs1, 0x6548, [(byte)0xE8, (byte)0x10, (byte)0x00]);
        // 017D:6548 call near 0x655B
        NearCall(cs1, 0x654B, unknown_017D_655B_07D2B);
        throw FailAsUntested("Call at 017D:6548 returned to 017D:654B, but no continuation was observed during discovery.");
    label_017D_6568_07D38_66:
        CheckExternalEvents(cs1, 0x6568);
        VerifySpeculativeEntryOrFail(cs1, 0x6568, [(byte)0x8C, (byte)0xC8]);
        // 017D:6568 mov AX,CS
        AX = CS;
        VerifySpeculativeEntryOrFail(cs1, 0x656A, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x03, (byte)0x00]);
        // 017D:656A add AX,word ptr CS:[3]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0003]);
        VerifySpeculativeEntryOrFail(cs1, 0x656F, [(byte)0x8E, (byte)0xC0]);
        // 017D:656F mov ES,AX
        ES = AX;
        VerifySpeculativeEntryOrFail(cs1, 0x6571, [(byte)0xBF, (byte)0x00, (byte)0x00]);
        // 017D:6571 mov DI,0
        DI = (ushort)0x0000;
        VerifySpeculativeEntryOrFail(cs1, 0x6574, [(byte)0x8B, (byte)0xF7]);
        // 017D:6574 mov SI,DI
        SI = DI;
        VerifySpeculativeEntryOrFail(cs1, 0x6576, [(byte)0xFC]);
        // 017D:6576 cld
        DirectionFlag = false;
        VerifySpeculativeEntryOrFail(cs1, 0x6577, [(byte)0xB9, (byte)0x00, (byte)0x01]);
        // 017D:6577 mov CX,0x0100
        CX = (ushort)0x0100;
        VerifySpeculativeEntryOrFail(cs1, 0x657A, [(byte)0xF3, (byte)0xA4]);
        // 017D:657A rep movs byte ptr ES:[DI],byte ptr DS:[SI]
        while (CX != (ushort)0x0000) {
            UInt8[ES, DI] = UInt8[DS, SI];
            SI = unchecked((ushort)(SI + unchecked((ushort)State.Direction8)));
            DI = unchecked((ushort)(DI + unchecked((ushort)State.Direction8)));
            CX = unchecked((ushort)(CX - (ushort)0x0001));
        }
        VerifySpeculativeEntryOrFail(cs1, 0x657C, [(byte)0x26, (byte)0x8C, (byte)0x1E, (byte)0x40, (byte)0x00]);
        // 017D:657C mov word ptr ES:[0x0040],DS
        UInt16[ES, (ushort)0x0040] = DS;
        VerifySpeculativeEntryOrFail(cs1, 0x6581, [(byte)0x8E, (byte)0xD8]);
        // 017D:6581 mov DS,AX
        DS = AX;
        VerifySpeculativeEntryOrFail(cs1, 0x6583, [(byte)0x8C, (byte)0x1E, (byte)0x09, (byte)0x00]);
        // 017D:6583 mov word ptr DS:[9],DS
        UInt16[DS, (ushort)0x0009] = DS;
        VerifySpeculativeEntryOrFail(cs1, 0x6587, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x05, (byte)0x00]);
        // 017D:6587 add AX,word ptr CS:[5]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0005]);
        VerifySpeculativeEntryOrFail(cs1, 0x658C, [(byte)0xA3, (byte)0x0F, (byte)0x00]);
        // 017D:658C mov word ptr DS:[0x000F],AX
        UInt16[DS, (ushort)0x000F] = AX;
        VerifySpeculativeEntryOrFail(cs1, 0x658F, [(byte)0x2E, (byte)0x03, (byte)0x06, (byte)0x09, (byte)0x00]);
        // 017D:658F add AX,word ptr CS:[9]
        AX = Alu16.Add(AX, UInt16[CS, (ushort)0x0009]);
        VerifySpeculativeEntryOrFail(cs1, 0x6594, [(byte)0xA3, (byte)0x15, (byte)0x00]);
        // 017D:6594 mov word ptr DS:[0x0015],AX
        UInt16[DS, (ushort)0x0015] = AX;
        VerifySpeculativeEntryOrFail(cs1, 0x6597, [(byte)0xB9, (byte)0x04, (byte)0x00]);
        // 017D:6597 mov CX,4
        CX = (ushort)0x0004;
        VerifySpeculativeEntryOrFail(cs1, 0x659A, [(byte)0x2E, (byte)0x8B, (byte)0x1E, (byte)0x07, (byte)0x00]);
        // 017D:659A mov BX,word ptr CS:[7]
        BX = UInt16[CS, (ushort)0x0007];
        VerifySpeculativeEntryOrFail(cs1, 0x659F, [(byte)0xD3, (byte)0xE3]);
        // 017D:659F shl BX,CL
        BX = Alu16.Shl(BX, unchecked((int)CL));
        VerifySpeculativeEntryOrFail(cs1, 0x65A1, [(byte)0x89, (byte)0x1E, (byte)0x12, (byte)0x00]);
        // 017D:65A1 mov word ptr DS:[0x0012],BX
        UInt16[DS, (ushort)0x0012] = BX;
        VerifySpeculativeEntryOrFail(cs1, 0x65A5, [(byte)0x9C]);
        // 017D:65A5 pushf
        Stack.Push16(FlagRegister16);
        VerifySpeculativeEntryOrFail(cs1, 0x65A6, [(byte)0x5A]);
        // 017D:65A6 pop DX
        DX = Stack.Pop16();
    label_017D_65A7_07D77_97:
        CheckExternalEvents(cs1, 0x65A7);
        VerifySpeculativeEntryOrFail(cs1, 0x65A7, [(byte)0xFA]);
        // 017D:65A7 cli
        InterruptFlag = false;
        VerifySpeculativeEntryOrFail(cs1, 0x65A8, [(byte)0x8E, (byte)0xD0]);
        // 017D:65A8 mov SS,AX
        SS = AX;
        State.InterruptShadowing = true;
        VerifySpeculativeEntryOrFail(cs1, 0x65AA, [(byte)0x8B, (byte)0xE3]);
        // 017D:65AA mov SP,BX
        SP = BX;
        VerifySpeculativeEntryOrFail(cs1, 0x65AC, [(byte)0xFB]);
        // 017D:65AC sti
        if (!InterruptFlag) {
            State.InterruptShadowing = true;
        }
        else {
        }
        InterruptFlag = true;
        throw FailAsUntested("Generated partition reached the end without a terminating control-flow instruction.");
    }

    public virtual Action unknown_017D_655B_07D2B(int loadOffset) {
    label_017D_655B_07D2B_73:
        CheckExternalEvents(cs1, 0x655B);
        VerifySpeculativeEntryOrFail(cs1, 0x655B, [(byte)0x8C, (byte)0xC8]);
        // 017D:655B mov AX,CS
        AX = CS;
        VerifySpeculativeEntryOrFail(cs1, 0x655D, [(byte)0x8E, (byte)0xD8]);
        // 017D:655D mov DS,AX
        DS = AX;
        VerifySpeculativeEntryOrFail(cs1, 0x655F, [(byte)0x5A]);
        // 017D:655F pop DX
        DX = Stack.Pop16();
        VerifySpeculativeEntryOrFail(cs1, 0x6560, [(byte)0xB4, (byte)0x09]);
        // 017D:6560 mov AH,9
        AH = (byte)0x09;
        VerifySpeculativeEntryOrFail(cs1, 0x6562, [(byte)0xCD, (byte)0x21]);
        // 017D:6562 int 0x21
        InterruptCall(cs1, 0x6564, unchecked((byte)((byte)0x21)));
        throw FailAsUntested("Call at 017D:6562 returned to 017D:6564, but no continuation was observed during discovery.");
    }

    public virtual Action provided_interrupt_handler_8_F000_0006_F0006(int loadOffset) {
    label_F000_0006_F0006_0:
        CheckExternalEvents(cs2, 0x0006);
        VerifySpeculativeEntryOrFail(cs2, 0x0006, [(byte)0xFE, (byte)0x38, (byte)0x08, (byte)0x00]);
        // F000:0006 callback 8
        Callback(unchecked((ushort)((ushort)0x0008)));
    label_F000_000A_F000A_1:
        CheckExternalEvents(cs2, 0x000A);
        VerifySpeculativeEntryOrFail(cs2, 0x000A, [(byte)0xCD, (byte)0x1C]);
        // F000:000A int 0x1C
        InterruptCall(cs2, 0x000C, unchecked((byte)((byte)0x1C)));
    label_F000_000C_F000C_4:
        CheckExternalEvents(cs2, 0x000C);
        VerifySpeculativeEntryOrFail(cs2, 0x000C, [(byte)0xFE, (byte)0x38, (byte)0x01, (byte)0x01]);
        // F000:000C callback 0x0101
        Callback(unchecked((ushort)((ushort)0x0101)));
    label_F000_0010_F0010_6:
        CheckExternalEvents(cs2, 0x0010);
        VerifySpeculativeEntryOrFail(cs2, 0x0010, [(byte)0xCF]);
        // F000:0010 iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_9_F000_0011_F0011(int loadOffset) {
    label_F000_0011_F0011_8:
        CheckExternalEvents(cs2, 0x0011);
        VerifySpeculativeEntryOrFail(cs2, 0x0011, [(byte)0xFE, (byte)0x38, (byte)0x09, (byte)0x00]);
        // F000:0011 callback 9
        Callback(unchecked((ushort)((ushort)0x0009)));
    label_F000_0015_F0015_9:
        CheckExternalEvents(cs2, 0x0015);
        VerifySpeculativeEntryOrFail(cs2, 0x0015, [(byte)0xCF]);
        // F000:0015 iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_70_F000_0057_F0057(int loadOffset) {
    label_F000_0057_F0057_12:
        CheckExternalEvents(cs2, 0x0057);
        VerifySpeculativeEntryOrFail(cs2, 0x0057, [(byte)0xFE, (byte)0x38, (byte)0x70, (byte)0x00]);
        // F000:0057 callback 0x0070
        Callback(unchecked((ushort)((ushort)0x0070)));
    label_F000_005B_F005B_13:
        CheckExternalEvents(cs2, 0x005B);
        VerifySpeculativeEntryOrFail(cs2, 0x005B, [(byte)0xCF]);
        // F000:005B iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_74_F000_005D_F005D(int loadOffset) {
    label_F000_005D_F005D_16:
        CheckExternalEvents(cs2, 0x005D);
        VerifySpeculativeEntryOrFail(cs2, 0x005D, [(byte)0x9A, (byte)0xE3, (byte)0x00, (byte)0x00, (byte)0xF0]);
        // F000:005D call far F000:00E3
        FarCall(cs2, 0x0062, cs2, provided_mouse_driver_F000_00E3_F00E3);
    label_F000_0062_F0062_20:
        CheckExternalEvents(cs2, 0x0062);
        VerifySpeculativeEntryOrFail(cs2, 0x0062, [(byte)0xFE, (byte)0x38, (byte)0x74, (byte)0x00]);
        // F000:0062 callback 0x0074
        Callback(unchecked((ushort)((ushort)0x0074)));
    label_F000_0066_F0066_24:
        CheckExternalEvents(cs2, 0x0066);
        VerifySpeculativeEntryOrFail(cs2, 0x0066, [(byte)0xCF]);
        // F000:0066 iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_B_F000_0067_F0067(int loadOffset) {
    label_F000_0067_F0067_32:
        CheckExternalEvents(cs2, 0x0067);
        VerifySpeculativeEntryOrFail(cs2, 0x0067, [(byte)0xFE, (byte)0x38, (byte)0x04, (byte)0x01]);
        // F000:0067 callback 0x0104
        Callback(unchecked((ushort)((ushort)0x0104)));
    label_F000_006B_F006B_33:
        CheckExternalEvents(cs2, 0x006B);
        VerifySpeculativeEntryOrFail(cs2, 0x006B, [(byte)0xCF]);
        // F000:006B iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_C_F000_006C_F006C(int loadOffset) {
    label_F000_006C_F006C_36:
        CheckExternalEvents(cs2, 0x006C);
        VerifySpeculativeEntryOrFail(cs2, 0x006C, [(byte)0xFE, (byte)0x38, (byte)0x05, (byte)0x01]);
        // F000:006C callback 0x0105
        Callback(unchecked((ushort)((ushort)0x0105)));
    label_F000_0070_F0070_37:
        CheckExternalEvents(cs2, 0x0070);
        VerifySpeculativeEntryOrFail(cs2, 0x0070, [(byte)0xCF]);
        // F000:0070 iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_D_F000_0071_F0071(int loadOffset) {
    label_F000_0071_F0071_40:
        CheckExternalEvents(cs2, 0x0071);
        VerifySpeculativeEntryOrFail(cs2, 0x0071, [(byte)0xFE, (byte)0x38, (byte)0x06, (byte)0x01]);
        // F000:0071 callback 0x0106
        Callback(unchecked((ushort)((ushort)0x0106)));
    label_F000_0075_F0075_41:
        CheckExternalEvents(cs2, 0x0075);
        VerifySpeculativeEntryOrFail(cs2, 0x0075, [(byte)0xCF]);
        // F000:0075 iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_F_F000_0076_F0076(int loadOffset) {
    label_F000_0076_F0076_44:
        CheckExternalEvents(cs2, 0x0076);
        VerifySpeculativeEntryOrFail(cs2, 0x0076, [(byte)0xFE, (byte)0x38, (byte)0x07, (byte)0x01]);
        // F000:0076 callback 0x0107
        Callback(unchecked((ushort)((ushort)0x0107)));
    label_F000_007A_F007A_45:
        CheckExternalEvents(cs2, 0x007A);
        VerifySpeculativeEntryOrFail(cs2, 0x007A, [(byte)0xCF]);
        // F000:007A iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_72_F000_007B_F007B(int loadOffset) {
    label_F000_007B_F007B_48:
        CheckExternalEvents(cs2, 0x007B);
        VerifySpeculativeEntryOrFail(cs2, 0x007B, [(byte)0xFE, (byte)0x38, (byte)0x08, (byte)0x01]);
        // F000:007B callback 0x0108
        Callback(unchecked((ushort)((ushort)0x0108)));
    label_F000_007F_F007F_49:
        CheckExternalEvents(cs2, 0x007F);
        VerifySpeculativeEntryOrFail(cs2, 0x007F, [(byte)0xCF]);
        // F000:007F iret
        return InterruptRet();
    }

    public virtual Action provided_interrupt_handler_73_F000_0080_F0080(int loadOffset) {
    label_F000_0080_F0080_52:
        CheckExternalEvents(cs2, 0x0080);
        VerifySpeculativeEntryOrFail(cs2, 0x0080, [(byte)0xFE, (byte)0x38, (byte)0x09, (byte)0x01]);
        // F000:0080 callback 0x0109
        Callback(unchecked((ushort)((ushort)0x0109)));
    label_F000_0084_F0084_53:
        CheckExternalEvents(cs2, 0x0084);
        VerifySpeculativeEntryOrFail(cs2, 0x0084, [(byte)0xCF]);
        // F000:0084 iret
        return InterruptRet();
    }

    public virtual Action unknown_F000_00E2_F00E2(int loadOffset) {
    label_F000_00E2_F00E2_26:
        CheckExternalEvents(cs2, 0x00E2);
        VerifySpeculativeEntryOrFail(cs2, 0x00E2, [(byte)0xCB]);
        // F000:00E2 ret far
        return FarRet((ushort)0x0000);
    }

    public virtual Action provided_mouse_driver_F000_00E3_F00E3(int loadOffset) {
    label_F000_00E3_F00E3_17:
        CheckExternalEvents(cs2, 0x00E3);
        VerifySpeculativeEntryOrFail(cs2, 0x00E3, [(byte)0xFE, (byte)0x38, (byte)0x0C, (byte)0x01]);
        // F000:00E3 callback 0x010C
        Callback(unchecked((ushort)((ushort)0x010C)));
    label_F000_00E7_F00E7_22:
        CheckExternalEvents(cs2, 0x00E7);
        VerifySpeculativeEntryOrFail(cs2, 0x00E7, [(byte)0x9A, (byte)0xE2, (byte)0x00, (byte)0x00, (byte)0xF0]);
        // F000:00E7 call far F000:00E2
        FarCall(cs2, 0x00EC, cs2, unknown_F000_00E2_F00E2);
    label_F000_00EC_F00EC_28:
        CheckExternalEvents(cs2, 0x00EC);
        VerifySpeculativeEntryOrFail(cs2, 0x00EC, [(byte)0xFE, (byte)0x38, (byte)0x0D, (byte)0x01]);
        // F000:00EC callback 0x010D
        Callback(unchecked((ushort)((ushort)0x010D)));
    label_F000_00F0_F00F0_30:
        CheckExternalEvents(cs2, 0x00F0);
        VerifySpeculativeEntryOrFail(cs2, 0x00F0, [(byte)0xCB]);
        // F000:00F0 ret far
        return FarRet((ushort)0x0000);
    }

}
