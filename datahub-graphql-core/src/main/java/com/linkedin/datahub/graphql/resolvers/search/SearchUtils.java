package com.linkedin.datahub.graphql.resolvers.search;

import com.datahub.authentication.Authentication;
import com.datahub.authorization.*;
import com.google.common.collect.ImmutableList;
import com.linkedin.common.urn.Urn;
import com.linkedin.data.template.StringArray;
import com.linkedin.datahub.graphql.QueryContext;
import com.linkedin.datahub.graphql.generated.EntityType;
import com.linkedin.datahub.graphql.generated.FacetFilterInput;
import com.linkedin.datahub.graphql.generated.Privileges;
import com.linkedin.datahub.graphql.resolvers.EntityTypeMapper;
import com.linkedin.datahub.graphql.types.common.mappers.SearchFlagsInputMapper;
import com.linkedin.metadata.authorization.PoliciesConfig;
import com.linkedin.metadata.query.SearchFlags;
import com.linkedin.metadata.query.filter.*;
import com.linkedin.metadata.service.ViewService;
import com.linkedin.policy.*;
import com.linkedin.view.DataHubViewInfo;
import com.datahub.authorization.PolicyEngine.*;

import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.extern.slf4j.Slf4j;
import org.codehaus.plexus.util.CollectionUtils;

import static com.linkedin.metadata.Constants.CHART_ENTITY_NAME;
import static com.linkedin.metadata.Constants.CONTAINER_ENTITY_NAME;
import static com.linkedin.metadata.Constants.CORP_GROUP_ENTITY_NAME;
import static com.linkedin.metadata.Constants.CORP_USER_ENTITY_NAME;
import static com.linkedin.metadata.Constants.DASHBOARD_ENTITY_NAME;
import static com.linkedin.metadata.Constants.DATASET_ENTITY_NAME;
import static com.linkedin.metadata.Constants.DATA_FLOW_ENTITY_NAME;
import static com.linkedin.metadata.Constants.DATA_JOB_ENTITY_NAME;
import static com.linkedin.metadata.Constants.DOMAIN_ENTITY_NAME;
import static com.linkedin.metadata.Constants.GLOSSARY_TERM_ENTITY_NAME;
import static com.linkedin.metadata.Constants.ML_FEATURE_ENTITY_NAME;
import static com.linkedin.metadata.Constants.ML_FEATURE_TABLE_ENTITY_NAME;
import static com.linkedin.metadata.Constants.ML_MODEL_ENTITY_NAME;
import static com.linkedin.metadata.Constants.ML_MODEL_GROUP_ENTITY_NAME;
import static com.linkedin.metadata.Constants.ML_PRIMARY_KEY_ENTITY_NAME;


@Slf4j
public class SearchUtils {
  private SearchUtils() {
  }

  /**
   * Entities that are searched by default in Search Across Entities
   */
  public static final List<EntityType> SEARCHABLE_ENTITY_TYPES =
          ImmutableList.of(
                  EntityType.DATASET,
                  EntityType.DASHBOARD,
                  EntityType.CHART,
                  EntityType.MLMODEL,
                  EntityType.MLMODEL_GROUP,
                  EntityType.MLFEATURE_TABLE,
                  EntityType.MLFEATURE,
                  EntityType.MLPRIMARY_KEY,
                  EntityType.DATA_FLOW,
                  EntityType.DATA_JOB,
                  EntityType.GLOSSARY_TERM,
                  EntityType.GLOSSARY_NODE,
                  EntityType.TAG,
                  EntityType.ROLE,
                  EntityType.CORP_USER,
                  EntityType.CORP_GROUP,
                  EntityType.CONTAINER,
                  EntityType.DOMAIN,
                  EntityType.DATA_PRODUCT,
                  EntityType.NOTEBOOK);


  /**
   * Entities that are part of autocomplete by default in Auto Complete Across Entities
   */
  public static final List<EntityType> AUTO_COMPLETE_ENTITY_TYPES =
          ImmutableList.of(
                  EntityType.DATASET,
                  EntityType.DASHBOARD,
                  EntityType.CHART,
                  EntityType.CONTAINER,
                  EntityType.MLMODEL,
                  EntityType.MLMODEL_GROUP,
                  EntityType.MLFEATURE_TABLE,
                  EntityType.DATA_FLOW,
                  EntityType.DATA_JOB,
                  EntityType.GLOSSARY_TERM,
                  EntityType.TAG,
                  EntityType.CORP_USER,
                  EntityType.CORP_GROUP,
                  EntityType.ROLE,
                  EntityType.NOTEBOOK,
                  EntityType.DATA_PRODUCT);

  /**
   * A prioritized list of source filter types used to generate quick filters
   */
  public static final List<String> PRIORITIZED_SOURCE_ENTITY_TYPES = Stream.of(
          DATASET_ENTITY_NAME,
          DASHBOARD_ENTITY_NAME,
          DATA_FLOW_ENTITY_NAME,
          DATA_JOB_ENTITY_NAME,
          CHART_ENTITY_NAME,
          CONTAINER_ENTITY_NAME,
          ML_MODEL_ENTITY_NAME,
          ML_MODEL_GROUP_ENTITY_NAME,
          ML_FEATURE_ENTITY_NAME,
          ML_FEATURE_TABLE_ENTITY_NAME,
          ML_PRIMARY_KEY_ENTITY_NAME
  ).map(String::toLowerCase).collect(Collectors.toList());

  /**
   * A prioritized list of DataHub filter types used to generate quick filters
   */
  public static final List<String> PRIORITIZED_DATAHUB_ENTITY_TYPES = Stream.of(
          DOMAIN_ENTITY_NAME,
          GLOSSARY_TERM_ENTITY_NAME,
          CORP_GROUP_ENTITY_NAME,
          CORP_USER_ENTITY_NAME
  ).map(String::toLowerCase).collect(Collectors.toList());

  /**
   * Entity Types String Mapper to map the Entity Types correctly due to various formats
   */
  private static final Map<String, EntityType> ENTITY_TYPE_MAP = Map.ofEntries(
          Map.entry("dataset", EntityType.DATASET),
          Map.entry("dashboard", EntityType.DASHBOARD),
          Map.entry("chart", EntityType.CHART),
          Map.entry("mlmodel", EntityType.MLMODEL),
          Map.entry("mlmodelgroup", EntityType.MLMODEL_GROUP),
          Map.entry("mlmodel_group", EntityType.MLMODEL_GROUP),
          Map.entry("mlfeaturetable", EntityType.MLFEATURE_TABLE),
          Map.entry("mlfeature_table", EntityType.MLFEATURE_TABLE),
          Map.entry("mlfeature", EntityType.MLFEATURE),
          Map.entry("mlprimarykey", EntityType.MLPRIMARY_KEY),
          Map.entry("mlprimary_key", EntityType.MLPRIMARY_KEY),
          Map.entry("dataflow", EntityType.DATA_FLOW),
          Map.entry("data_flow", EntityType.DATA_FLOW),
          Map.entry("datajob", EntityType.DATA_JOB),
          Map.entry("data_job", EntityType.DATA_JOB),
          Map.entry("glossaryterm", EntityType.GLOSSARY_TERM),
          Map.entry("glossary_term", EntityType.GLOSSARY_TERM),
          Map.entry("glossarynode", EntityType.GLOSSARY_NODE),
          Map.entry("glossary_node", EntityType.GLOSSARY_NODE),
          Map.entry("tag", EntityType.TAG),
          Map.entry("role", EntityType.ROLE),
          Map.entry("corpuser", EntityType.CORP_USER),
          Map.entry("corp_user", EntityType.CORP_USER),
          Map.entry("corpgroup", EntityType.CORP_GROUP),
          Map.entry("corp_group", EntityType.CORP_GROUP),
          Map.entry("container", EntityType.CONTAINER),
          Map.entry("domain", EntityType.DOMAIN),
          Map.entry("dataproduct", EntityType.DATA_PRODUCT),
          Map.entry("data_product", EntityType.DATA_PRODUCT),
          Map.entry("notebook", EntityType.NOTEBOOK)
  );

  /**
   * Combines two {@link Filter} instances in a conjunction and returns a new instance of {@link Filter}
   * in disjunctive normal form.
   *
   * @param baseFilter the filter to apply the view to
   * @param viewFilter the view filter, null if it doesn't exist
   * @return a new instance of {@link Filter} representing the applied view.
   */
  @Nonnull
  public static Filter combineFilters(@Nullable final Filter baseFilter, @Nonnull final Filter viewFilter) {
    final Filter finalBaseFilter = baseFilter == null
            ? new Filter().setOr(new ConjunctiveCriterionArray(Collections.emptyList()))
            : baseFilter;

    // Join the filter conditions in Disjunctive Normal Form.
    return combineFiltersInConjunction(finalBaseFilter, viewFilter);
  }

  /**
   * Returns the intersection of two sets of entity types. (Really just string lists).
   * If either is empty, consider the entity types list to mean "all" (take the other set).
   *
   * @param baseEntityTypes the entity types to apply the view to
   * @param viewEntityTypes the view info, null if it doesn't exist
   * @return the intersection of the two input sets
   */
  @Nonnull
  public static List<String> intersectEntityTypes(@Nonnull final List<String> baseEntityTypes, @Nonnull final List<String> viewEntityTypes) {
    if (baseEntityTypes.isEmpty()) {
      return viewEntityTypes;
    }
    if (viewEntityTypes.isEmpty()) {
      return baseEntityTypes;
    }
    // Join the entity types in intersection.
    return new ArrayList<>(CollectionUtils.intersection(baseEntityTypes, viewEntityTypes));
  }

  /**
   * Joins two filters in conjunction by reducing to Disjunctive Normal Form.
   *
   * @param filter1 the first filter in the pair
   * @param filter2 the second filter in the pair
   *                <p>
   *                This method supports either Filter format, where the "or" field is used, instead
   *                of criteria. If the criteria filter is used, then it will be converted into an "OR" before
   *                returning the new filter.
   * @return the result of joining the 2 filters in a conjunction (AND)
   * <p>
   * How does it work? It basically cross-products the conjunctions inside of each Filter clause.
   * <p>
   * Example Inputs:
   * filter1 ->
   * {
   * or: [
   * {
   * and: [
   * {
   * field: tags,
   * condition: EQUAL,
   * values: ["urn:li:tag:tag"]
   * }
   * ]
   * },
   * {
   * and: [
   * {
   * field: glossaryTerms,
   * condition: EQUAL,
   * values: ["urn:li:glossaryTerm:term"]
   * }
   * ]
   * }
   * ]
   * }
   * filter2 ->
   * {
   * or: [
   * {
   * and: [
   * {
   * field: domain,
   * condition: EQUAL,
   * values: ["urn:li:domain:domain"]
   * },
   * ]
   * },
   * {
   * and: [
   * {
   * field: glossaryTerms,
   * condition: EQUAL,
   * values: ["urn:li:glossaryTerm:term2"]
   * }
   * ]
   * }
   * ]
   * }
   * Example Output:
   * {
   * or: [
   * {
   * and: [
   * {
   * field: tags,
   * condition: EQUAL,
   * values: ["urn:li:tag:tag"]
   * },
   * {
   * field: domain,
   * condition: EQUAL,
   * values: ["urn:li:domain:domain"]
   * }
   * ]
   * },
   * {
   * and: [
   * {
   * field: tags,
   * condition: EQUAL,
   * values: ["urn:li:tag:tag"]
   * },
   * {
   * field: glossaryTerms,
   * condition: EQUAL,
   * values: ["urn:li:glosaryTerm:term2"]
   * }
   * ]
   * },
   * {
   * and: [
   * {
   * field: glossaryTerm,
   * condition: EQUAL,
   * values: ["urn:li:glossaryTerm:term"]
   * },
   * {
   * field: domain,
   * condition: EQUAL,
   * values: ["urn:li:domain:domain"]
   * }
   * ]
   * },
   * {
   * and: [
   * {
   * field: glossaryTerm,
   * condition: EQUAL,
   * values: ["urn:li:glossaryTerm:term"]
   * },
   * {
   * field: glossaryTerms,
   * condition: EQUAL,
   * values: ["urn:li:glosaryTerm:term2"]
   * }
   * ]
   * },
   * ]
   * }
   */
  @Nonnull
  private static Filter combineFiltersInConjunction(@Nonnull final Filter filter1, @Nonnull final Filter filter2) {

    final Filter finalFilter1 = convertToV2Filter(filter1);
    final Filter finalFilter2 = convertToV2Filter(filter2);

    // If either filter is empty, simply return the other filter.
    if (!finalFilter1.hasOr() || finalFilter1.getOr().size() == 0) {
      return finalFilter2;
    }
    if (!finalFilter2.hasOr() || finalFilter2.getOr().size() == 0) {
      return finalFilter1;
    }

    // Iterate through the base filter, then cross-product with filter 2 conditions.
    final Filter result = new Filter();
    final List<ConjunctiveCriterion> newDisjunction = new ArrayList<>();
    for (ConjunctiveCriterion conjunction1 : finalFilter1.getOr()) {
      for (ConjunctiveCriterion conjunction2 : finalFilter2.getOr()) {
        final List<Criterion> joinedCriterion = new ArrayList<>(conjunction1.getAnd());
        joinedCriterion.addAll(conjunction2.getAnd());
        ConjunctiveCriterion newConjunction = new ConjunctiveCriterion().setAnd(new CriterionArray(joinedCriterion));
        newDisjunction.add(newConjunction);
      }
    }
    result.setOr(new ConjunctiveCriterionArray(newDisjunction));
    return result;
  }

  @Nonnull
  private static Filter convertToV2Filter(@Nonnull Filter filter) {
    if (filter.hasOr()) {
      return filter;
    } else if (filter.hasCriteria()) {
      // Convert criteria to an OR
      return new Filter()
              .setOr(new ConjunctiveCriterionArray(ImmutableList.of(
                      new ConjunctiveCriterion()
                              .setAnd(filter.getCriteria())
              )));
    }
    throw new IllegalArgumentException(
            String.format("Illegal filter provided! Neither 'or' nor 'criteria' fields were populated for filter %s", filter));
  }

  /**
   * Attempts to resolve a View by urn. Throws {@link IllegalArgumentException} if a View with the specified
   * urn cannot be found.
   */
  public static DataHubViewInfo resolveView(@Nonnull ViewService viewService, @Nonnull final Urn viewUrn,
                                            @Nonnull final Authentication authentication) {
    try {
      DataHubViewInfo maybeViewInfo = viewService.getViewInfo(viewUrn, authentication);
      if (maybeViewInfo == null) {
        log.warn(String.format("Failed to resolve View with urn %s. View does not exist!", viewUrn));
      }
      return maybeViewInfo;
    } catch (Exception e) {
      throw new RuntimeException(String.format("Caught exception while attempting to resolve View with URN %s", viewUrn), e);
    }
  }

  //  Assumption is that filter values for degree are either null, 3+, 2, or 1.
  public static Integer getMaxHops(List<FacetFilterInput> filters) {
    Set<String> degreeFilterValues = filters.stream()
            .filter(filter -> filter.getField().equals("degree"))
            .flatMap(filter -> filter.getValues().stream())
            .collect(Collectors.toSet());
    Integer maxHops = null;
    if (!degreeFilterValues.contains("3+")) {
      if (degreeFilterValues.contains("2")) {
        maxHops = 2;
      } else if (degreeFilterValues.contains("1")) {
        maxHops = 1;
      }
    }
    return maxHops;
  }

  public static SearchFlags mapInputFlags(com.linkedin.datahub.graphql.generated.SearchFlags inputFlags) {
    SearchFlags searchFlags = null;
    if (inputFlags != null) {
      searchFlags = SearchFlagsInputMapper.INSTANCE.apply(inputFlags);
    }
    return searchFlags;
  }

  public static SortCriterion mapSortCriterion(com.linkedin.datahub.graphql.generated.SortCriterion sortCriterion) {
    SortCriterion result = new SortCriterion();
    result.setField(sortCriterion.getField());
    result.setOrder(SortOrder.valueOf(sortCriterion.getSortOrder().name()));
    return result;
  }

  public static List<String> getEntityNames(List<EntityType> inputTypes) {
    final List<EntityType> entityTypes =
            (inputTypes == null || inputTypes.isEmpty()) ? SEARCHABLE_ENTITY_TYPES : inputTypes;
    return entityTypes.stream().map(EntityTypeMapper::getName).collect(Collectors.toList());
  }

  /**
   * Modify the filter from the resolver to pass only those entities with the required permission
   */
  public static Filter handleResolver(Filter baseFilter, PrivilegeInfoAcrossEntities privilegeInfoAcrossEntities, String entityType) {
    EntityPrivilegeInfo entityPrivilegeInfo = privilegeInfoAcrossEntities.getEntityPrivilegeInfo(entityType);

    if (entityPrivilegeInfo.isAppliedOnAllResources()) {
      return baseFilter;
    }

    if (!entityPrivilegeInfo.getUrnsWithThisPrivilege().isEmpty()) {
      List<String> urns = entityPrivilegeInfo.getUrnsWithThisPrivilege().stream().map(Urn::toString).collect(Collectors.toList());
      Criterion criterion = createCriterion("urn", Condition.EQUAL,urns.get(0),new StringArray(urns));
      baseFilter.getOr().get(0).getAnd().add(criterion);
      return baseFilter;
    }

    // Don't let any entity pass
    baseFilter.getOr().get(0).getAnd().get(0).setField("null");
    return baseFilter;
  }

  public static Criterion createCriterion(String field, Condition condition, String value, StringArray values) {
    Criterion criterion = new Criterion();
    criterion.setField(field);
    criterion.setCondition(condition);
    criterion.setValue(value);
    criterion.setValues(values);
    return criterion;
  }

  public static Filter getAuthorizedBaseFilter(QueryContext context, Filter baseFilter, String sourceType) {

    List<String> entityTypes = SEARCHABLE_ENTITY_TYPES.stream().map(entityType -> entityType.toString().replace("_", "").toLowerCase()).collect(Collectors.toList());
    DataHubAuthorizer dataHubAuthorizer = ((AuthorizerChain) context.getAuthorizer()).getDefaultAuthorizer();
    PrivilegeInfoAcrossEntities privilegeInfoAcrossEntities = dataHubAuthorizer.getPrivilegeInfoAcrossEntities(entityTypes, PoliciesConfig.VIEW_ENTITY_PAGE_PRIVILEGE, context.getActorUrn());

    // If Privilege is Applied Globally privilegeInfoAcrossEntities is null hence no modification needed
    if (privilegeInfoAcrossEntities == null) {
      return baseFilter;
    }

    // Modify the filter from the resolver to pass only those entities with the required permission
    if (sourceType.equals("ListDomainsResolver")) {
      return handleResolver(baseFilter, privilegeInfoAcrossEntities, "domain");
    }

    if (sourceType.equals("GetRootGlossaryNodesResolver")) {
      return handleResolver(baseFilter, privilegeInfoAcrossEntities, "glossarynode");
    }

    if (sourceType.equals("GetRootGlossaryTermsResolver")) {
      return handleResolver(baseFilter, privilegeInfoAcrossEntities, "glossaryterm");
    }

    //REMOVE DUPLICATE URNS.....

    // Create a filter with Entity Types with Global permission and entities with the permission
    Filter modifiedFilter = new Filter();
    ConjunctiveCriterionArray conjunctiveCriterionArray = new ConjunctiveCriterionArray();

    StringArray entityTypeWithPermissionArray = new StringArray();
    StringArray urnWithPermissionArray = new StringArray();

    for (String entityType : entityTypes) {
      EntityPrivilegeInfo entityPrivilegeInfo = privilegeInfoAcrossEntities.getEntityPrivilegeInfo(entityType);
      if (entityPrivilegeInfo.isAppliedOnAllResources()) {
        entityTypeWithPermissionArray.add(entityPrivilegeInfo.getEntityType());
      } else if (!entityPrivilegeInfo.getUrnsWithThisPrivilege().isEmpty()) {
        List<String> urns = entityPrivilegeInfo.getUrnsWithThisPrivilege().stream().map(Urn::toString).collect(Collectors.toList());
        urnWithPermissionArray.addAll(urns);
      }
    }

    if (!entityTypeWithPermissionArray.isEmpty()) {
      Criterion criterion = createCriterion("_entityType", Condition.EQUAL, entityTypeWithPermissionArray.get(0), entityTypeWithPermissionArray);

      CriterionArray criterionArray = new CriterionArray();
      ConjunctiveCriterion conjunctiveCriterion = new ConjunctiveCriterion();

      criterionArray.add(criterion);
      conjunctiveCriterion.setAnd(criterionArray);
      conjunctiveCriterionArray.add(conjunctiveCriterion);
    }

    if (!urnWithPermissionArray.isEmpty()) {
      Criterion criterion = createCriterion("urn", Condition.EQUAL, entityTypeWithPermissionArray.get(0), urnWithPermissionArray);

      CriterionArray criterionArray = new CriterionArray();
      ConjunctiveCriterion conjunctiveCriterion = new ConjunctiveCriterion();

      criterionArray.add(criterion);
      conjunctiveCriterion.setAnd(criterionArray);

      conjunctiveCriterionArray.add(conjunctiveCriterion);
    }

    // If user hasn't selected any filter, pass the modified filter that filters outs entities without the permission
    if (baseFilter == null) {
      modifiedFilter.setOr(conjunctiveCriterionArray);
      return modifiedFilter;
    }

    boolean foundEntityType = false;

    ConjunctiveCriterionArray conjunctiveCriterionArray2 = baseFilter.getOr();

    for (ConjunctiveCriterion conjunctiveCriterion : conjunctiveCriterionArray2) {

      for (Criterion criterion : conjunctiveCriterion.getAnd()) {
        String field = criterion.getField();
        String value = criterion.getValue();

        if (field.equals("_entityType")) {
          foundEntityType = true;
          String formattedEntityType = value.replace("_", "").toLowerCase();
          EntityPrivilegeInfo entityPrivilegeInfo = privilegeInfoAcrossEntities.getEntityPrivilegeInfo(formattedEntityType);
          if (!entityPrivilegeInfo.isAppliedOnAllResources()) {
            criterion.setField("urn");
            if (entityPrivilegeInfo.getUrnsWithThisPrivilege().isEmpty()) {
              criterion.setValue("");
            } else {
              List<String> urns = entityPrivilegeInfo.getUrnsWithThisPrivilege().stream().map(Urn::toString).collect(Collectors.toList());
              criterion.setValue(urns.get(0));
              criterion.setValues(new StringArray(urns));
            }
          }

        }
      }
    }

    // If baseFilter doesn't have any entityType filter specified, modify the current filter to include them so that only
    // entities with required permission are passed
    if (!foundEntityType) {

      ConjunctiveCriterionArray conjunctiveCriterionArrayFinal = baseFilter.getOr();
      ConjunctiveCriterionArray conjunctiveCriterionArrayToSend = new ConjunctiveCriterionArray();
      CriterionArray criterionArrayFinal = conjunctiveCriterionArrayFinal.get(0).getAnd();

      for (String entityType : entityTypes) {

        EntityPrivilegeInfo entityPrivilegeInfo = privilegeInfoAcrossEntities.getEntityPrivilegeInfo(entityType);
        Criterion criterion = new Criterion();
        criterion.setCondition(Condition.EQUAL);

        if (entityPrivilegeInfo.isAppliedOnAllResources()) {
          criterion.setField("_entityType");
          criterion.setValue(entityPrivilegeInfo.getEntityType());
          criterion.setValues(new StringArray(entityPrivilegeInfo.getEntityType()));
        } else if (!entityPrivilegeInfo.getUrnsWithThisPrivilege().isEmpty()) {
          criterion.setField("urn");
          List<String> urns = entityPrivilegeInfo.getUrnsWithThisPrivilege().stream().map(Urn::toString).collect(Collectors.toList());
          criterion.setValue(urns.get(0));
          criterion.setValues(new StringArray(urns));
        } else {
          continue;
        }

        CriterionArray criterionArrayCopy = new CriterionArray();
        criterionArrayCopy.addAll(criterionArrayFinal);
        criterionArrayCopy.add(criterion);

        ConjunctiveCriterion conjunctiveCriterion = new ConjunctiveCriterion();
        conjunctiveCriterion.setAnd(criterionArrayCopy);
        conjunctiveCriterionArrayToSend.add(conjunctiveCriterion);

      }

      baseFilter.setOr(conjunctiveCriterionArrayToSend);
    }

    return baseFilter;
  }
}
