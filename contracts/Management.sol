// SPDX-License-Identifier: PROPRIERTARY

// Author: Ilya A. Shlyakhovoy
// Email: ilya@zionodes.com

import "@openzeppelin/contracts/access/manager/AccessManager.sol";

pragma solidity ^0.8.20;


import "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./Voting.sol";
import "./interfaces/IManagement.sol";

/// @title An administrative management contract
/// @author Ilya A. Shlyakhovoy
/// @notice This contract manage any functions of the contracts using call.
/// It support 3 different management levels - community level, manager level and administrator level.

contract Management is IManagement, AccessManager, AccessManaged, Voting {
    using EnumerableSet for EnumerableSet.AddressSet;
    uint64 public constant OWNER_ROLE = 10;
    uint64 public constant MANAGER_ROLE = 20;
    uint64 public constant COMMUNITY_ROLE = 30;

    struct CalleeDefine {
        address caller;
        address target;
        bytes4 selector;
    }

    EnumerableSet.AddressSet private owners;
    EnumerableSet.AddressSet private managers;
    address private community;
    uint256 private votesNeeded;
    uint256 private ownersLimit;
    CalleeDefine[] private callees;

/*     struct ManageAction {
        address target;
        address author;
        uint256 expiration;
        bytes4 signature;
        bytes data;
        bool executed;
    }
    using Counters for Counters.Counter;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using EnumerableSet for EnumerableSet.AddressSet;
    Counters.Counter private _actionIndex;
    IERC20 private _token;
    address private _initialOwner;
    address private _remainsAddress;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER");
    bytes32 public constant TOKEN = keccak256("TOKEN");
    bytes32 public constant DURATION = keccak256("DURATION");
    bytes32 public constant TARGET = keccak256("TARGET");

    address[3] private _admins;
    EnumerableSet.AddressSet private _managers;
    EnumerableMap.AddressToUintMap private _promilles;
    mapping(uint256 => ManageAction) private _actions;
    uint256 private _duration;
    address private _newAdmin;
    address private _newAdminProposer;
 */
/* 
    /// @notice only if one of the admins calls
    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), NOT_ADMIN);
        _;
    }
    /// @notice only if admin called or contract is not sealed and owner called
    modifier protected() {
        require(
            (!_sealed && _initialOwner == msg.sender) ||
                hasRole(ADMIN_ROLE, msg.sender),
            PROTECTED
        );
        _;
    }

    /// @notice only if manager or admin called
    modifier onlyAdminOrManager() {
        require(
            hasRole(ADMIN_ROLE, msg.sender) ||
                hasRole(MANAGER_ROLE, msg.sender),
            NOT_TRUSTED
        );
        _;
    }
 */
    /// @notice constructor
    /// @param _duration The lifetime of third-party call in seconds
   
    constructor(
        uint256 _duration, address _community
       ) AccessManager(msg.sender), AccessManaged(address(0)) {
        community = _community;
        ownersLimit = 1;
        votesNeeded = 1;
        _grantOwner(msg.sender);
        grantRole(AccessManager.ADMIN_ROLE, address(this), 0);
        revokeRole(AccessManager.ADMIN_ROLE, msg.sender);
    }

    function init() {
        setAuthority(this);
    }
    /**
    * @notice Set the amount of owners and the number of votes needed for the one decision
    * @param total_ The new amount of the owners
    * @param votesNeeded_ The new amount of the minimal votes needed ( 0 < votes <= total)
    **/
    function setOwnerLimits(uint256 total_, uint256 votesNeeded_) public restricted {
        if (total_ < owners.length()) {
            revert NoOwnersNumberLessThanCurrent(total, owners.length());
        };
        if (total_ < votesNeeded_) {
            revert NoOwnersNumberLessThanVotes(total, votesNeeded_);
        };
        if (votesNeeded_ < 1) {
            revert VotesNumberTooSmall(votesNeeded_);
        };
        votesNeeded = votesNeeded_;
        ownersLimit = total_;
        emit OwnerLimitsDefined(total_, votesNeeded_)
    }

    function grantOwner(address target_) restricted {
        _grantOwner(target);
    }

    function _grantOwner(address target_) {
         if (owners.length() >= ownersLimit) {
            revert NoMoreOwnersPossible(target_, owners.length());
        };
        if (owners.contains(target_) ) {
            revert OwnerAlreadyDefined(target_);
        };
        if (target_ == community) {
            revert OwnerCannotBeCommunity(target_);
        };
        grantRole(OWNER_ROLE, target_, 0);
        owners.add(target_)
        emit OwnerGranted(target_);
    }


    function revokeOwner(address target_) restricted {
        if (!owners.contains(target_) ) {
            revert OwnerNotDefined(target_);
        };
        if (owners.length() <= votesNeeded_ ) {
            revert TooManyOwnersForVoting(target_, owners.length() , votesNeeded_);
        };
        revokeRole(OWNER_ROLE, target_);
        owners.remove(target_);
        emit OwnerRevoked(target_);
    }

    function grantManager(address target_) { 
        if (managers.contains(target_) ) {
            revert ManagerAlreadyDefined(target_);
        };
        if (target_ == community) {
            revert ManagerCannotBeCommunity(target_);
        };
        grantRole(MANAGER_ROLE, target_, 0);
        managers.add(target_)
        emit ManagerGranted(target_);
    }

    function revokeManager(address target_) restricted {
        if (!managers.contains(target_) ) {
            revert ManagerNotDefined(target_);
        }; 
        revokeRole(MANAGER_ROLE, target_);
        managers.remove(target_);
        emit ManagerRevoked(target_);
    }

     function canCall(
        address caller,
        address target,
        bytes4 selector
    ) public view virtual override returns (bool immediate, uint32 delay) {
        return _voting();
    };

    function _voting() internal returns (bool) {
        if (owners.contains(msg.sender) && owners.length()==1) {
            return true;
        }
    }

    /**
@notice Adding a new  
@param newAdmin New admin address

**/

    /**
@notice Add a new admin from the owner's side (only while contract is not sealed)
@param newAdmin New admin address


    function addAdmin(address newAdmin)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        notSealed
    {
        for (uint256 i = 0; i < 3; ++i) {
            require(_admins[i] != newAdmin, DUP_ADMINS);
            if (_admins[i] == address(0)) {
                _admins[i] = newAdmin;
                grantRole(ADMIN_ROLE, newAdmin);
                emit AdminAdded(newAdmin);
                return;
            }
        }
        require(false, ALL_SET);
    }
*/
    /**
@notice The list of the admins. Can be called only by admin
@return The list of current admins
*/

    function admins() external view onlyAdmin returns (address[3] memory) {
        return _admins;
    }

    /**
@notice Get the lifetime of the third-party call
@return The lifetime in seconds
*/
    function duration() external view returns (uint256) {
        return _duration;
    }

    /**
@notice Set the lifetime of the third-party call
@param duration_ The lifetime of third-party call in seconds
*/
    function setDuration(uint256 duration_) external protected {
        if (!_sealed) {
            _duration = duration_;
            emit DurationChanged(msg.sender, duration_);
        }
        require(!hasVote(DURATION, msg.sender), DUP_VOTE);
        bytes32 encoded = keccak256(abi.encode(duration_));
        if (!isVoteExists(DURATION)) {
            _openVote(DURATION, 2, encoded);
            emit DurationChangeRequest(msg.sender, duration_);
        }
        _vote(DURATION, encoded);
        if (isVoteResolved(DURATION)) {
            _duration = duration_;
            _closeVote(DURATION);
            emit DurationChanged(msg.sender, duration_);
        }
    }

    /**
@notice Get the current token address
@return The token's address
*/
    function token() external view returns (address) {
        return address(_token);
    }

    /**
@notice Set the address of the distributed token
@param token_ The address of the token distributed
*/
    function setToken(address token_) external protected {
        if (!_sealed) {
            _token = IERC20(token_);
            emit TokenChanged(msg.sender, token_);
            return;
        }
        require(!hasVote(TOKEN, msg.sender), DUP_VOTE);
        bytes32 encodedToken = keccak256(abi.encode(token_));
        if (!isVoteExists(TOKEN)) {
            _openVote(TOKEN, 2, encodedToken);
            emit TokenChangeRequest(msg.sender, token_);
        }
        _vote(TOKEN, encodedToken);
        if (isVoteResolved(TOKEN)) {
            _token = IERC20(token_);
            _closeVote(TOKEN);
            emit TokenChanged(msg.sender, token_);
        }
    }

    /**
@notice Get the address where non-distributed tokens should go
@return The target's wallet address
*/
    function target() external view returns (address) {
        return _remainsAddress;
    }

    /**
@notice Set the address where non-distributed tokens should go
@param target_ The address of the token distributed
*/
    function setTarget(address target_) external protected {
        if (!_sealed) {
            _remainsAddress = target_;
            emit TargetChanged(msg.sender, target_);
            return;
        }
        require(!hasVote(TARGET, msg.sender), DUP_VOTE);
        bytes32 encodedTarget = keccak256(abi.encode(target_));
        if (!isVoteExists(TARGET)) {
            _openVote(TARGET, 2, encodedTarget);
            emit TargetChangeRequest(msg.sender, target_);
        }
        _vote(TARGET, encodedTarget);
        if (isVoteResolved(TARGET)) {
            _remainsAddress = target_;
            _closeVote(TARGET);
            emit TargetChanged(msg.sender, target_);
        }
    }

    /// @notice Seal the contract (will not be accessible by owner)
    function seal() external onlyRole(DEFAULT_ADMIN_ROLE) notSealed {
        for (uint256 i = 0; i < 3; ++i) {
            require(_admins[i] != address(0), NOT_ALL);
        }
        _sealed = true;
        _setRoleAdmin(ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        renounceRole(DEFAULT_ADMIN_ROLE, _initialOwner);
    }

    /**
@notice Set the new admin instead of the one old (with voting)
If two of the different admins offers the same address, the third of
the admins will be changed to the new address. Any admin offering a
new address starting the voting procedure again.
@param newAdmin The address of the admin wallet
*/
    function changeAdmin(address newAdmin) external onlyAdmin isSealed {
        require(newAdmin != address(0), ZERO_ADDRESS);
        require(!hasRole(ADMIN_ROLE, newAdmin), EXISTING_ADMIN);
        require(
            newAdmin != _newAdmin || _newAdminProposer != msg.sender,
            DUP_OFFER
        );
        if (newAdmin != _newAdmin) {
            _newAdmin = newAdmin;
            _newAdminProposer = msg.sender;
            emit AdminChangePending(msg.sender, newAdmin);
            return;
        }
        for (uint256 i = 0; i < 3; ++i) {
            if (_admins[i] != _newAdminProposer && _admins[i] != msg.sender) {
                address oldAdmin = _admins[i];
                _admins[i] = newAdmin;
                _newAdmin = address(0);
                revokeRole(ADMIN_ROLE, oldAdmin);
                grantRole(ADMIN_ROLE, newAdmin);
                emit AdminChanged(msg.sender, oldAdmin, newAdmin);
                return;
            }
        }
        require(false, STRANGE);
    }

    /**
@notice Get the amount of the actions
@return The number of the all actions added
*/
    function actionsLength() public view isSealed returns (uint256) {
        return _actionIndex.current();
    }

    /**
@notice Get the action
@param index The id of the action
@return The action data
*/
    function getAction(uint256 index)
        public
        view
        isSealed
        returns (ManageAction memory)
    {
        require(index < _actionIndex.current(), BIG_INDEX);
        return _actions[index];
    }

    /**
@notice Add the new manager by owner
@param manager The address of the manager
*/
    function addManager(address manager) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(manager != address(0), ZERO_ADDRESS);
        grantRole(MANAGER_ROLE, manager);
        _managers.add(manager);
        emit ManagerAdded(manager);
    }

    /**
@notice Remove the manager by owner
@param manager The address of the manager
*/
    function removeManager(address manager)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(manager != address(0), ZERO_ADDRESS);
        revokeRole(MANAGER_ROLE, manager);
        _managers.remove(manager);
        emit ManagerRemoved(manager);
    }

    /**
@notice List of managers 
*/
    function managers()
        external
        view
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (address[] memory)
    {
        return _managers.values();
    }

    /**
@notice Add the action. It can be called by manager (with no vote) or admin (with vote)
@param target_ The address of the calling contract
@param signature The signature (keccak256(abi.bytesEncoded(function name, parameters)))
@param data The abi.bytesEncoded(data)
@return The id of the new action
*/
    function addAction(
        address target_,
        bytes4 signature,
        bytes memory data
    ) external isSealed onlyAdminOrManager returns (uint256) {
        address author = address(0);
        if (hasRole(ADMIN_ROLE, msg.sender)) {
            author = msg.sender;
        }
        uint256 current = _actionIndex.current();
        _actions[current] = ManageAction({
            target: target_,
            signature: signature,
            data: data,
            author: author,
            executed: false,
            expiration: _duration + block.timestamp
        });
        emit ActionAdded(current, msg.sender, target_, signature);
        if (hasRole(ADMIN_ROLE, msg.sender)) {
            emit ActionSigned(current, msg.sender);
        }
        _actionIndex.increment();
        return current;
    }

    /**
@notice Voting and execution of the action (if votes enough)
@param index The id of the action
@return The result of the call
*/
    function executeAction(uint256 index)
        external
        isSealed
        onlyAdmin
        returns (bytes memory)
    {
        require(index < _actionIndex.current(), BIG_INDEX);
        require(_actions[index].expiration >= block.timestamp, TOO_LATE);
        require(!_actions[index].executed, EXECUTED);
        require(_actions[index].author != msg.sender, DUP_ADMINS);
        if (_actions[index].author == address(0)) {
            _actions[index].author = msg.sender;
            emit ActionSigned(index, msg.sender);
            return "";
        }
        (bool success, bytes memory data) = _actions[index].target.call(
            abi.encodePacked(_actions[index].signature, _actions[index].data)
        );
        _actions[index].executed = success;
        require(success, FAILED);
        emit ActionExecuted(index, msg.sender);
        return data;
    }
}
