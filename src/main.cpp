#include <iostream>
#include <intkey-circuit-gl1.hpp>

using std::cout;
using std::endl;
using namespace libsnark;

int main() {
    ppT::init_public_params();

    IntkeyCircuit circuit;
    circuit.generate();

    uint32_t my_secret_value = 33;
    InputAndProof input_and_proof = circuit.prove(my_secret_value);

    if(circuit.verify(input_and_proof))
        cout << "Valid Proof" << endl;
    else
        cout << "DANGER Invalid Proof" << endl;

    return 0;
}