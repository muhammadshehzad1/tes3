package com.datahub.authorization;

import com.datahub.authentication.Authentication;
import com.linkedin.common.Owner;
import com.linkedin.common.Ownership;
import com.linkedin.common.urn.Urn;
import com.linkedin.common.urn.UrnUtils;
import com.linkedin.data.template.StringArray;
import com.linkedin.entity.EntityResponse;
import com.linkedin.entity.EnvelopedAspect;
import com.linkedin.entity.EnvelopedAspectMap;
import com.linkedin.entity.client.EntityClient;
import com.linkedin.identity.RoleMembership;
import com.linkedin.metadata.Constants;
import com.linkedin.metadata.authorization.PoliciesConfig;
import com.linkedin.policy.DataHubActorFilter;
import com.linkedin.policy.DataHubPolicyInfo;
import com.linkedin.policy.DataHubResourceFilter;
import com.linkedin.policy.PolicyMatchCondition;
import com.linkedin.policy.PolicyMatchCriterion;
import com.linkedin.policy.PolicyMatchCriterionArray;
import com.linkedin.policy.PolicyMatchFilter;

import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import static com.linkedin.metadata.Constants.*;


@Slf4j
@RequiredArgsConstructor
public class PolicyEngine {

  private final Authentication _systemAuthentication;
  private final EntityClient _entityClient;

  public PolicyEvaluationResult evaluatePolicy(
          final DataHubPolicyInfo policy,
          final ResolvedEntitySpec resolvedActorSpec,
          final String privilege,
          final Optional<ResolvedEntitySpec> resource) {

    final PolicyEvaluationContext context = new PolicyEvaluationContext();
    log.debug("Evaluating policy {}", policy.getDisplayName());

    // If the privilege is not in scope, deny the request.
    if (!isPrivilegeMatch(privilege, policy.getPrivileges())) {
      log.debug("Policy denied based on irrelevant privileges {} for {}", policy.getPrivileges(), privilege);
      return PolicyEvaluationResult.DENIED;
    }

    // If policy is not applicable, deny the request
    if (!isPolicyApplicable(policy, resolvedActorSpec, resource, context)) {
      log.debug("Policy does not applicable for actor {} and resource {}", resolvedActorSpec.getSpec().getEntity(), resource);
      return PolicyEvaluationResult.DENIED;
    }

    // All portions of the Policy match. Grant the request.
    return PolicyEvaluationResult.GRANTED;
  }

  public PolicyActors getMatchingActors(
          final DataHubPolicyInfo policy,
          final Optional<ResolvedEntitySpec> resource) {
    final List<Urn> users = new ArrayList<>();
    final List<Urn> groups = new ArrayList<>();
    boolean allUsers = false;
    boolean allGroups = false;
    if (policyMatchesResource(policy, resource)) {
      // Step 3: For each matching policy, find actors that are authorized.
      final DataHubActorFilter actorFilter = policy.getActors();

      // 0. Determine if we have a wildcard policy.
      if (actorFilter.isAllUsers()) {
        allUsers = true;
      }
      if (actorFilter.isAllUsers()) {
        allGroups = true;
      }

      // 1. Populate actors listed on the policy directly.
      if (actorFilter.getUsers() != null) {
        users.addAll(actorFilter.getUsers());
      }
      if (actorFilter.getGroups() != null) {
        groups.addAll(actorFilter.getGroups());
      }

      // 2. Fetch Actors based on resource ownership.
      if (actorFilter.isResourceOwners() && resource.isPresent()) {
        Set<String> owners = resource.get().getOwners();
        users.addAll(userOwners(owners));
        groups.addAll(groupOwners(owners));
      }
    }
    return new PolicyActors(users, groups, allUsers, allGroups);
  }

  private boolean isPolicyApplicable(
          final DataHubPolicyInfo policy,
          final ResolvedEntitySpec resolvedActorSpec,
          final Optional<ResolvedEntitySpec> resource,
          final PolicyEvaluationContext context
  ) {

    // If policy is inactive, simply return DENY.
    if (PoliciesConfig.INACTIVE_POLICY_STATE.equals(policy.getState())) {
      return false;
    }

    // If the resource is not in scope, deny the request.
    if (!isResourceMatch(policy.getType(), policy.getResources(), resource)) {
      return false;
    }

    // If the actor does not match, deny the request.
    return isActorMatch(resolvedActorSpec, policy.getActors(), resource, context);
  }

  public List<String> getGrantedPrivileges(
          final List<DataHubPolicyInfo> policies,
          final ResolvedEntitySpec resolvedActorSpec,
          final Optional<ResolvedEntitySpec> resource) {
    PolicyEvaluationContext context = new PolicyEvaluationContext();
    return policies.stream()
            .filter(policy -> isPolicyApplicable(policy, resolvedActorSpec, resource, context))
            .flatMap(policy -> policy.getPrivileges().stream())
            .distinct()
            .collect(Collectors.toList());
  }

  /**
   * Returns true if the policy matches the resource spec, false otherwise.
   *
   * If the policy is of type "PLATFORM", the resource will always match (since there's no resource).
   * If the policy is of type "METADATA", the resourceSpec parameter will be matched against the
   * resource filter defined on the policy.
   */
  public Boolean policyMatchesResource(final DataHubPolicyInfo policy, final Optional<ResolvedEntitySpec> resourceSpec) {
    return isResourceMatch(policy.getType(), policy.getResources(), resourceSpec);
  }

  /**
   * Returns true if the privilege portion of a DataHub policy matches a the privilege being evaluated, false otherwise.
   */
  private boolean isPrivilegeMatch(
          final String requestPrivilege,
          final List<String> policyPrivileges) {
    return policyPrivileges.contains(requestPrivilege);
  }

  /**
   * Returns true if the resource portion of a DataHub policy matches a the resource being evaluated, false otherwise.
   */
  private boolean isResourceMatch(
          final String policyType,
          final @Nullable DataHubResourceFilter policyResourceFilter,
          final Optional<ResolvedEntitySpec> requestResource) {
    if (PoliciesConfig.PLATFORM_POLICY_TYPE.equals(policyType)) {
      // Currently, platform policies have no associated resource.
      return true;
    }
    if (policyResourceFilter == null) {
      // No resource defined on the policy.
      return true;
    }
    if (requestResource.isEmpty()) {
      // Resource filter present in policy, but no resource spec provided.
      log.debug("Resource filter present in policy, but no resource spec provided.");
      return false;
    }
    final PolicyMatchFilter filter = getFilter(policyResourceFilter);
    return checkFilter(filter, requestResource.get());
  }

  /**
   * Get filter object from policy resource filter. Make sure it is backward compatible by constructing PolicyMatchFilter object
   * from other fields if the filter field is not set
   */
  public PolicyMatchFilter getFilter(DataHubResourceFilter policyResourceFilter) {
    if (policyResourceFilter.hasFilter()) {
      return policyResourceFilter.getFilter();
    }
    PolicyMatchCriterionArray criteria = new PolicyMatchCriterionArray();
    if (policyResourceFilter.hasType()) {
      criteria.add(new PolicyMatchCriterion().setField(EntityFieldType.TYPE.name())
              .setValues(new StringArray(Collections.singletonList(policyResourceFilter.getType()))));
    }
    if (policyResourceFilter.hasType() && policyResourceFilter.hasResources()
            && !policyResourceFilter.isAllResources()) {
      criteria.add(
              new PolicyMatchCriterion().setField(EntityFieldType.URN.name()).setValues(policyResourceFilter.getResources()));
    }
    return new PolicyMatchFilter().setCriteria(criteria);
  }

  private boolean checkFilter(final PolicyMatchFilter filter, final ResolvedEntitySpec resource) {
    return filter.getCriteria().stream().allMatch(criterion -> checkCriterion(criterion, resource));
  }

  private boolean checkCriterion(final PolicyMatchCriterion criterion, final ResolvedEntitySpec resource) {
    EntityFieldType entityFieldType;
    try {
      entityFieldType = EntityFieldType.valueOf(criterion.getField().toUpperCase());
    } catch (IllegalArgumentException e) {
      log.error("Unsupported field type {}", criterion.getField());
      return false;
    }

    Set<String> fieldValues = resource.getFieldValues(entityFieldType);
    return criterion.getValues()
            .stream()
            .anyMatch(filterValue -> checkCondition(fieldValues, filterValue, criterion.getCondition()));
  }

  private boolean checkCondition(Set<String> fieldValues, String filterValue, PolicyMatchCondition condition) {
    if (condition == PolicyMatchCondition.EQUALS) {
      return fieldValues.contains(filterValue);
    }
    log.error("Unsupported condition {}", condition);
    return false;
  }

  /**
   * Returns true if the actor portion of a DataHub policy matches a the actor being evaluated, false otherwise.
   * Returns true if the actor portion of a DataHub policy matches a the actor being evaluated, false otherwise.
   */
  private boolean isActorMatch(
          final ResolvedEntitySpec resolvedActorSpec,
          final DataHubActorFilter actorFilter,
          final Optional<ResolvedEntitySpec> resourceSpec,
          final PolicyEvaluationContext context) {

    // 1. If the actor is a matching "User" in the actor filter, return true immediately.
    if (isUserMatch(resolvedActorSpec, actorFilter)) {
      return true;
    }

    // 2. If the actor is in a matching "Group" in the actor filter, return true immediately.
    if (isGroupMatch(resolvedActorSpec, actorFilter, context)) {
      return true;
    }

    // 3. If the actor is the owner, either directly or indirectly via a group, return true immediately.
    if (isOwnerMatch(resolvedActorSpec, actorFilter, resourceSpec, context)) {
      return true;
    }

    // 4. If the actor is in a matching "Role" in the actor filter, return true immediately.
    return isRoleMatch(resolvedActorSpec, actorFilter, context);
  }

  public boolean isUserMatch(final ResolvedEntitySpec resolvedActorSpec, final DataHubActorFilter actorFilter) {
    // If the actor is a matching "User" in the actor filter, return true immediately.
    return actorFilter.isAllUsers() || (actorFilter.hasUsers() && Objects.requireNonNull(actorFilter.getUsers())
            .stream().map(Urn::toString)
            .anyMatch(user -> user.equals(resolvedActorSpec.getSpec().getEntity())));
  }

  public boolean isGroupMatch(
          final ResolvedEntitySpec resolvedActorSpec,
          final DataHubActorFilter actorFilter,
          final PolicyEvaluationContext context) {
    // If the actor is in a matching "Group" in the actor filter, return true immediately.
    if (actorFilter.isAllGroups() || actorFilter.hasGroups()) {
      final Set<String> groups = resolveGroups(resolvedActorSpec, context);
      return (actorFilter.isAllGroups() && !groups.isEmpty())
              || (actorFilter.hasGroups() && Objects.requireNonNull(actorFilter.getGroups())
              .stream().map(Urn::toString)
              .anyMatch(groups::contains));
    }
    // If there are no groups on the policy, return false for the group match.
    return false;
  }

  public boolean isOwnerMatch(
          final ResolvedEntitySpec resolvedActorSpec,
          final DataHubActorFilter actorFilter,
          final Optional<ResolvedEntitySpec> requestResource,
          final PolicyEvaluationContext context) {
    // If the policy does not apply to owners, or there is no resource to own, return false immediately.
    if (!actorFilter.isResourceOwners() || requestResource.isEmpty()) {
      return false;
    }
    List<Urn> ownershipTypes = actorFilter.getResourceOwnersTypes();
    return isActorOwner(resolvedActorSpec, requestResource.get(), ownershipTypes, context);
  }

  private Set<String> getOwnersForType(EntitySpec resourceSpec, List<Urn> ownershipTypes) {
    Urn entityUrn = UrnUtils.getUrn(resourceSpec.getEntity());
    EnvelopedAspect ownershipAspect;
    try {
      EntityResponse response = _entityClient.getV2(entityUrn.getEntityType(), entityUrn,
              Collections.singleton(Constants.OWNERSHIP_ASPECT_NAME), _systemAuthentication);
      if (response == null || !response.getAspects().containsKey(Constants.OWNERSHIP_ASPECT_NAME)) {
        return Collections.emptySet();
      }
      ownershipAspect = response.getAspects().get(Constants.OWNERSHIP_ASPECT_NAME);
    } catch (Exception e) {
      log.error("Error while retrieving ownership aspect for urn {}", entityUrn, e);
      return Collections.emptySet();
    }
    Ownership ownership = new Ownership(ownershipAspect.getValue().data());
    Stream<Owner> ownersStream = ownership.getOwners().stream();
    if (ownershipTypes != null) {
      ownersStream = ownersStream.filter(owner -> ownershipTypes.contains(owner.getTypeUrn()));
    }
    return ownersStream.map(owner -> owner.getOwner().toString()).collect(Collectors.toSet());
  }

  private boolean isActorOwner(
          final ResolvedEntitySpec resolvedActorSpec,
          ResolvedEntitySpec resourceSpec, List<Urn> ownershipTypes,
          PolicyEvaluationContext context) {
    Set<String> owners = this.getOwnersForType(resourceSpec.getSpec(), ownershipTypes);
    if (isUserOwner(resolvedActorSpec, owners)) {
      return true;
    }
    final Set<String> groups = resolveGroups(resolvedActorSpec, context);

    return isGroupOwner(groups, owners);
  }

  private boolean isUserOwner(final ResolvedEntitySpec resolvedActorSpec, Set<String> owners) {
    return owners.contains(resolvedActorSpec.getSpec().getEntity());
  }

  private boolean isGroupOwner(Set<String> groups, Set<String> owners) {
    return groups.stream().anyMatch(owners::contains);
  }

  private boolean isRoleMatch(
          final ResolvedEntitySpec resolvedActorSpec,
          final DataHubActorFilter actorFilter,
          final PolicyEvaluationContext context) {
    // Can immediately return false if the actor filter does not have any roles
    if (!actorFilter.hasRoles()) {
      return false;
    }
    // If the actor has a matching "Role" in the actor filter, return true immediately.
    Set<Urn> actorRoles = resolveRoles(resolvedActorSpec, context);
    return Objects.requireNonNull(actorFilter.getRoles())
            .stream()
            .anyMatch(actorRoles::contains);
  }

  private Set<Urn> resolveRoles(final ResolvedEntitySpec resolvedActorSpec, PolicyEvaluationContext context) {
    if (context.roles != null) {
      return context.roles;
    }

    String actor = resolvedActorSpec.getSpec().getEntity();

    Set<Urn> roles = new HashSet<>();
    final EnvelopedAspectMap aspectMap;

    try {
      Urn actorUrn = Urn.createFromString(actor);
      final EntityResponse corpUser = _entityClient.batchGetV2(CORP_USER_ENTITY_NAME, Collections.singleton(actorUrn),
              Collections.singleton(ROLE_MEMBERSHIP_ASPECT_NAME), _systemAuthentication).get(actorUrn);
      if (corpUser == null || !corpUser.hasAspects()) {
        return roles;
      }
      aspectMap = corpUser.getAspects();
    } catch (Exception e) {
      log.error(String.format("Failed to fetch %s for urn %s", ROLE_MEMBERSHIP_ASPECT_NAME, actor), e);
      return roles;
    }

    if (!aspectMap.containsKey(ROLE_MEMBERSHIP_ASPECT_NAME)) {
      return roles;
    }

    RoleMembership roleMembership = new RoleMembership(aspectMap.get(ROLE_MEMBERSHIP_ASPECT_NAME).getValue().data());
    if (roleMembership.hasRoles()) {
      roles.addAll(roleMembership.getRoles());
      context.setRoles(roles);
    }
    return roles;
  }

  private Set<String> resolveGroups(ResolvedEntitySpec resolvedActorSpec, PolicyEvaluationContext context) {
    if (context.groups != null) {
      return context.groups;
    }

    Set<String> groups = resolvedActorSpec.getGroupMembership();

    context.setGroups(groups); // Cache the groups.
    return groups;
  }

  /**
   * Class used to store state across a single Policy evaluation.
   */
  public static class PolicyEvaluationContext {
    private Set<String> groups;
    private Set<Urn> roles;

    public void setGroups(Set<String> groups) {
      this.groups = groups;
    }

    public void setRoles(Set<Urn> roles) {
      this.roles = roles;
    }
  }

  /**
   * Class used to represent the result of a Policy evaluation
   */
  static class PolicyEvaluationResult {
    public static final PolicyEvaluationResult GRANTED = new PolicyEvaluationResult(true);
    public static final PolicyEvaluationResult DENIED = new PolicyEvaluationResult(false);

    private final boolean isGranted;

    private PolicyEvaluationResult(boolean isGranted) {
      this.isGranted = isGranted;
    }

    public boolean isGranted() {
      return this.isGranted;
    }
  }

  /**
   * Class used to represent all valid users of a policy.
   */
  public static class PolicyActors {
    final List<Urn> _users;
    final List<Urn> _groups;
    final Boolean _allUsers;
    final Boolean _allGroups;

    public PolicyActors(final List<Urn> users, final List<Urn> groups, final Boolean allUsers, final Boolean allGroups) {
      _users = users;
      _groups = groups;
      _allUsers = allUsers;
      _allGroups = allGroups;
    }

    public List<Urn> getUsers() {
      return _users;
    }

    public List<Urn> getGroups() {
      return _groups;
    }

    public Boolean allUsers() {
      return _allUsers;
    }

    public Boolean allGroups() {
      return _allGroups;
    }
  }

  private List<Urn> userOwners(final Set<String> owners) {
    return owners.stream()
            .map(UrnUtils::getUrn)
            .filter(owner -> CORP_USER_ENTITY_NAME.equals(owner.getEntityType()))
            .collect(Collectors.toList());
  }

  private List<Urn> groupOwners(final Set<String> owners) {
    return owners.stream()
            .map(UrnUtils::getUrn)
            .filter(owner -> CORP_GROUP_ENTITY_NAME.equals(owner.getEntityType()))
            .collect(Collectors.toList());
  }

  /**
   * Gets info regarding a particular privilege access across all entities
   */
  public PrivilegeInfoAcrossEntities getPrivilegeInfoAcrossEntities(List<String> entityTypes, PoliciesConfig.Privilege privilege, List<DataHubPolicyInfo> policiesToEvaluate, ResolvedEntitySpec resolvedActorSpec, EntitySpecResolver entitySpecResolver) {

    PrivilegeInfoAcrossEntities privilegeInfoAcrossEntities = new PrivilegeInfoAcrossEntities(entityTypes,privilege);
    PolicyEvaluationContext policyEvaluationContext = new PolicyEvaluationContext();
    boolean isUserOrGroupMatch;

    // Evaluate each policy.
    for (DataHubPolicyInfo policy : policiesToEvaluate) {

      // If Policy not applicable move to new policy
      if (!isPolicyApplicable(policy)) {
        continue;
      }

      isUserOrGroupMatch = isUserOrGroupMatch(resolvedActorSpec, policy.getActors(), policyEvaluationContext);
      DataHubResourceFilter policyResourceFilter = policy.getResources();

      // If no filter applied, then privilege is applied globally
      if (policyResourceFilter == null) {
        if (isUserOrGroupMatch) {
          return null;
        }
        continue;
      }

      PolicyMatchCriterionArray criterionArray = getFilter(policyResourceFilter).getCriteria();
      // If criterionArray is empty, then privilege is applied globally
      if (criterionArray.isEmpty() && isUserOrGroupMatch) {
        return null;
      }

      CriterionArrayInfo criterionArrayInfo = new CriterionArrayInfo();
      criterionArray.forEach(criterionArrayInfo::addCriteria);

      // If no EntityType is defined then privilege is applied globally
      if (!criterionArrayInfo.hasTypeField()) {
        return null;
      }

      AtomicBoolean domainEntityFound = new AtomicBoolean(false);

      if (!criterionArrayInfo.hasUrnField()) {

        // If EntityType is defined but UrnField is not defined then specified EntityTypes have specified privilege
        if (isUserOrGroupMatch) {
          criterionArrayInfo.getTypeCriterion().getValues().forEach(entityType -> {
            String formattedEntityType = entityType.replace("_", "").toLowerCase();

            if (formattedEntityType.equals("domain")) {
              domainEntityFound.set(true);
            }
            privilegeInfoAcrossEntities.getEntityPrivilegeInfo(formattedEntityType).setAppliedOnAllResources(true);
          });
        }
      } else {
        boolean finalisUserOrGroupMatch = isUserOrGroupMatch;
        criterionArrayInfo.getUrnCriterion().getValues().forEach(rawUrn -> {
          Urn urn;
          try {
            urn = new Urn(rawUrn);
          } catch (URISyntaxException e) {
            throw new RuntimeException(e);
          }

          if (finalisUserOrGroupMatch || isOwnerMatch(resolvedActorSpec,policy.getActors(),getResolvedEntitySpec(Optional.of(new EntitySpec(urn.getEntityType().toLowerCase(),urn.toString())), entitySpecResolver),policyEvaluationContext)) {
            String formattedEntityType = urn.getEntityType().replace("_", "").toLowerCase();
            privilegeInfoAcrossEntities.getEntityPrivilegeInfo(formattedEntityType).getUrnsWithThisPrivilege().add(urn);
          }

        });
      }

      // If domainField exists then add the domain urns if authorized.
      if(criterionArrayInfo.hasDomainField() && domainEntityFound.get()) {
        boolean finalIsActorAuthorized1 = isUserOrGroupMatch;
        criterionArrayInfo.getDomainCriterion().getValues().forEach(rawUrn -> {
          Urn urn;
          try {
            urn = new Urn(rawUrn);
          } catch (URISyntaxException e) {
            throw new RuntimeException(e);
          }

          if (finalIsActorAuthorized1 || isOwnerMatch(resolvedActorSpec,policy.getActors(),getResolvedEntitySpec(Optional.of(new EntitySpec(urn.getEntityType().toLowerCase(),urn.toString())),entitySpecResolver),policyEvaluationContext)) {
            String formattedEntityType = urn.getEntityType().replace("_", "").toLowerCase();
            privilegeInfoAcrossEntities.getEntityPrivilegeInfo(formattedEntityType).getUrnsWithThisPrivilege().add(urn);
          }
        });
      }
    }

    return privilegeInfoAcrossEntities;

  }


  private boolean isPolicyApplicable(DataHubPolicyInfo policy) {

    // If Platform policy, continue
    if (PoliciesConfig.PLATFORM_POLICY_TYPE.equals(policy.getType())) {
      return false;
    }

    // If policy is inactive, continue.
    return !PoliciesConfig.INACTIVE_POLICY_STATE.equals(policy.getState());

  }

  private boolean isUserOrGroupMatch( ResolvedEntitySpec resolvedActorSpec, DataHubActorFilter actorFilter, PolicyEvaluationContext policyEvaluationContext) {
    return isUserMatch(resolvedActorSpec, actorFilter) || isGroupMatch(resolvedActorSpec, actorFilter, policyEvaluationContext);
  }

  public static class PrivilegeInfoAcrossEntities {
    private final HashMap<String, EntityPrivilegeInfo> privilegeInfoAcrossEntities;

    public PrivilegeInfoAcrossEntities(List<String> entityTypes, PoliciesConfig.Privilege privilege) {
      privilegeInfoAcrossEntities = new HashMap<>();
      entityTypes.forEach(entityType -> privilegeInfoAcrossEntities.put(entityType, new EntityPrivilegeInfo(entityType, privilege)));
    }

    public EntityPrivilegeInfo getEntityPrivilegeInfo(String entityType) {
      return privilegeInfoAcrossEntities.get(entityType);
    }
  }

  private Optional<ResolvedEntitySpec> getResolvedEntitySpec(Optional<EntitySpec> entitySpec, EntitySpecResolver entitySpecResolver) {
    return  entitySpec.map(entitySpecResolver::resolve);
  }

  @Setter
  @Getter
  public static class EntityPrivilegeInfo {
    private PoliciesConfig.Privilege privilege;
    private String entityType;
    private boolean appliedOnAllResources = false;
    private HashSet<Urn> urnsWithThisPrivilege;


    public EntityPrivilegeInfo(String entityType, PoliciesConfig.Privilege privilege) {
      setPrivilege(privilege);
      setEntityType(entityType);
      setAppliedOnAllResources(false);
      setUrnsWithThisPrivilege(new HashSet<>());
    }


  }

  @Getter
  @Setter
  public static class CriterionArrayInfo {
    private boolean typeField = false;
    private PolicyMatchCriterion typeCriterion;

    private boolean urnField = false;
    private PolicyMatchCriterion urnCriterion;

    private boolean domainField = false;
    private PolicyMatchCriterion domainCriterion;

    public void addCriteria(PolicyMatchCriterion criterion) {

      if (criterion.getField().equals("TYPE")){
        setTypeField(true);
        setTypeCriterion(criterion);
      } else if (criterion.getField().equals("URN")) {
        setUrnField(true);
        setUrnCriterion(criterion);
      } else if(criterion.getField().equals("DOMAIN")) {
        setDomainField(true);
        setDomainCriterion(criterion);
      }
    }

    public boolean hasDomainField() {
      return domainField;
    }

    public boolean hasTypeField() {
      return typeField;
    }

    public boolean hasUrnField() {
      return urnField;
    }

  }

}
