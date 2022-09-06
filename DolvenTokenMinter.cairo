%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import assert_not_zero
from starkware.starknet.common.syscalls import get_caller_address, get_block_timestamp, deploy
from starkware.cairo.common.alloc import alloc

from starkware.cairo.common.bool import TRUE, FALSE
from openzeppelin.access.ownable import Ownable

@storage_var
func deployedContracts(nonce : felt) -> (contract_address : felt):
end

@storage_var
func deployedContractsByUser(userAddress : felt, deploy_nonce : felt) -> (contract_address : felt):
end

@storage_var
func salt() -> (current_salt : felt):
end

@storage_var
func user_nonce(user_address : felt) -> (user_nonce : felt):
end

@storage_var
func class_hash() -> (hash : felt):
end

@event
func Deployed(address : felt, user_from : felt, timestamp : felt):
end

# # Getters

@view
func get_deployed_contracts{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    ) -> (addresses_len : felt, addresses : felt*):
    let (addresses_len, addresses) = recursiveContractAddresses(0)
    return (addresses_len, addresses - addresses_len)
end

@view
func get_deployed_contracts_by_user{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}(user_address : felt) -> (addresses_len : felt, addresses : felt*):
    let (addresses_len, addresses) = recursiveContractAddressesByUser(0, user_address)
    return (addresses_len, addresses - addresses_len)
end

@view
func get_salt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    _salt : felt
):
    let (_salt : felt) = salt.read()
    return (_salt)
end

# #External Functions

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _classHash : felt
):
    class_hash.write(_classHash)
    return ()
end

@external
func deployNewToken{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    tokenName : felt, tokenDecimal : felt, tokenSupply : felt, tokenTicker : felt
):
    alloc_locals
    # # Category 1
    let call_data_array : felt* = alloc()
    let (msg_sender) = get_caller_address()
    assert call_data_array[0] = tokenName
    assert call_data_array[1] = tokenDecimal
    assert call_data_array[2] = tokenSupply
    assert call_data_array[3] = tokenTicker
    assert call_data_array[4] = msg_sender

    let _salt : felt = salt.read()
    let _classHash : felt = class_hash.read()

    let (new_contract_address : felt) = deploy(
        class_hash=_classHash,
        contract_address_salt=_salt,
        constructor_calldata_size=5,
        constructor_calldata=call_data_array,
        deploy_from_zero=FALSE,
    )
    let _userNonce : felt = user_nonce.read(msg_sender)
    deployedContracts.write(_salt, new_contract_address)
    deployedContractsByUser.write(msg_sender, _userNonce, new_contract_address)

    let (time) = get_block_timestamp()
    salt.write(_salt + 1)
    user_nonce.write(msg_sender, _userNonce + 1)
    Deployed.emit(new_contract_address, msg_sender, time)
    return ()
end

# # Internal Functions

func recursiveContractAddresses{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    address_nonce : felt
) -> (addresses_len : felt, addresses : felt*):
    alloc_locals
    let _salt : felt = salt.read()
    let contract_address : felt = deployedContracts.read(address_nonce)
    if address_nonce == _salt:
        let (found_addresses : felt*) = alloc()
        return (0, found_addresses)
    end

    let (
        address_memory_location_len, addresss_memory_location : felt*
    ) = recursiveContractAddresses(address_nonce + 1)
    assert [addresss_memory_location] = contract_address
    return (address_memory_location_len + 1, addresss_memory_location + 1)
end

func recursiveContractAddressesByUser{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr
}(address_nonce : felt, userAddress : felt) -> (addresses_len : felt, addresses : felt*):
    alloc_locals
    let _user_nonce : felt = user_nonce.read(userAddress)
    let contract_address : felt = deployedContractsByUser.read(userAddress, address_nonce)
    if address_nonce == _user_nonce:
        let (found_addresses : felt*) = alloc()
        return (0, found_addresses)
    end

    let (
        address_memory_location_len, addresss_memory_location : felt*
    ) = recursiveContractAddressesByUser(address_nonce + 1, userAddress)
    assert [addresss_memory_location] = contract_address
    return (address_memory_location_len + 1, addresss_memory_location + 1)
end
