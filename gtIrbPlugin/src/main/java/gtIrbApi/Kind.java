/** */
package gtIrbApi;

/** @author tneale */
public enum Kind {
    Node(0),
    CfgNode(1),
    Block(2),
    ProxyBlock(3),
    LAST_CfgNode(3),
    DataObject(4),
    ImageByteMap(5),
    IR(6),
    Module(7),
    Section(8),
    Symbol(9),
    LAST_Node(9);

    private int value;

    private Kind(int value) {
        this.value = value;
    }
};
