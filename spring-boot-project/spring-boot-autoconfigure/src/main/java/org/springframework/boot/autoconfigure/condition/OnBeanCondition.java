/*
 * Copyright 2012-2018 the original author or authors.
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

package org.springframework.boot.autoconfigure.condition;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.HierarchicalBeanFactory;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.boot.autoconfigure.condition.BeanTypeRegistry.TypeExtractor;
import org.springframework.boot.autoconfigure.condition.ConditionMessage.Style;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

/**
 * {@link Condition} that checks for the presence or absence of specific beans.
 *
 * @author Phillip Webb
 * @author Dave Syer
 * @author Jakub Kubrynski
 * @author Stephane Nicoll
 * @author Andy Wilkinson
 * @see ConditionalOnBean
 * @see ConditionalOnMissingBean
 * @see ConditionalOnSingleCandidate
 */
@Order(Ordered.LOWEST_PRECEDENCE)
class OnBeanCondition extends FilteringSpringBootCondition
		implements ConfigurationCondition {

	/**
	 * Bean definition attribute name for factory beans to signal their product type (if
	 * known and it can't be deduced from the factory bean class).
	 */
	public static final String FACTORY_BEAN_OBJECT_TYPE = BeanTypeRegistry.FACTORY_BEAN_OBJECT_TYPE;

	@Override
	public ConfigurationPhase getConfigurationPhase() {
		return ConfigurationPhase.REGISTER_BEAN;
	}
	// 批量的对自动配置类进行匹配
	@Override
	protected final ConditionOutcome[] getOutcomes(String[] autoConfigurationClasses,
												   AutoConfigurationMetadata autoConfigurationMetadata) {
		ConditionOutcome[] outcomes = new ConditionOutcome[autoConfigurationClasses.length];
		for (int i = 0; i < outcomes.length; i++) {
			String autoConfigurationClass = autoConfigurationClasses[i];
			if (autoConfigurationClass != null) {
				Set<String> onBeanTypes = autoConfigurationMetadata
						.getSet(autoConfigurationClass, "ConditionalOnBean");
				outcomes[i] = getOutcome(onBeanTypes, ConditionalOnBean.class);
				if (outcomes[i] == null) {
					Set<String> onSingleCandidateTypes = autoConfigurationMetadata.getSet(
							autoConfigurationClass, "ConditionalOnSingleCandidate");
					outcomes[i] = getOutcome(onSingleCandidateTypes,
							ConditionalOnSingleCandidate.class);
				}
			}
		}
		return outcomes;
	}

	private ConditionOutcome getOutcome(Set<String> requiredBeanTypes,
										Class<? extends Annotation> annotation) {
		List<String> missing = filter(requiredBeanTypes, ClassNameFilter.MISSING,
				getBeanClassLoader());
		if (!missing.isEmpty()) {
			ConditionMessage message = ConditionMessage.forCondition(annotation)
					.didNotFind("required type", "required types")
					.items(Style.QUOTE, missing);
			return ConditionOutcome.noMatch(message);
		}
		return null;
	}

	//这里是通过三个注解来判断的：
	// 1、@ConditionalOnBean：容器里有指定的bean则返回成功的结果。
	// 2、@ConditionalOnSingleCandidate：父子容器内有且只有一个的bean则返回成功的消息
	// 3、@ConditionalOnMissingBean：容器内查询到则返回失败的结果。
	@Override
	public ConditionOutcome getMatchOutcome(ConditionContext context,
											AnnotatedTypeMetadata metadata) {
		ConditionMessage matchMessage = ConditionMessage.empty();
		// 判断有没有 @ConditionalOnBean 注解
		if (metadata.isAnnotated(ConditionalOnBean.class.getName())) {
			BeanSearchSpec spec = new BeanSearchSpec(context, metadata,
					ConditionalOnBean.class);
			// 先通过bean类型查找，然后是通过注解方式查找，最后是通过beanName查找，返回查找结果
			MatchResult matchResult = getMatchingBeans(context, spec);
			// 没有全部匹配成功（注解、bean 名和 类型三者没有全部匹配上），则返回匹配失败的结果。
			if (!matchResult.isAllMatched()) {
				String reason = createOnBeanNoMatchReason(matchResult);
				return ConditionOutcome.noMatch(ConditionMessage
						.forCondition(ConditionalOnBean.class, spec).because(reason));
			}
			// 到这里说明全部匹配成功了，则添加匹配成功的信息。
			matchMessage = matchMessage.andCondition(ConditionalOnBean.class, spec)
					.found("bean", "beans")
					.items(Style.QUOTE, matchResult.getNamesOfAllMatches());
		}
		// 如果存在 @ConditionalOnSingleCandidate 注解
		if (metadata.isAnnotated(ConditionalOnSingleCandidate.class.getName())) {
			BeanSearchSpec spec = new SingleCandidateBeanSearchSpec(context, metadata,
					ConditionalOnSingleCandidate.class);
			MatchResult matchResult = getMatchingBeans(context, spec);
			// 没有全部匹配上返回一个匹配失败的信息
			if (!matchResult.isAllMatched()) {
				return ConditionOutcome.noMatch(ConditionMessage
						.forCondition(ConditionalOnSingleCandidate.class, spec)
						.didNotFind("any beans").atAll());
			}
			// 如果匹配出Bean的个数超过1个，则说明匹配这个类型的不唯一返回失败的结果。
			else if (!hasSingleAutowireCandidate(context.getBeanFactory(),
					matchResult.getNamesOfAllMatches(),
					spec.getStrategy() == SearchStrategy.ALL)) {
				return ConditionOutcome.noMatch(ConditionMessage
						.forCondition(ConditionalOnSingleCandidate.class, spec)
						.didNotFind("a primary bean from beans")
						.items(Style.QUOTE, matchResult.getNamesOfAllMatches()));
			}
			// 返回匹配成功写消息
			matchMessage = matchMessage
					.andCondition(ConditionalOnSingleCandidate.class, spec)
					.found("a primary bean from beans")
					.items(Style.QUOTE, matchResult.getNamesOfAllMatches());
		}
		// 判断有没有 @ConditionalOnMissingBean 注解，如果找到我们要 missing 的bean则返回失败的结果
		if (metadata.isAnnotated(ConditionalOnMissingBean.class.getName())) {
			BeanSearchSpec spec = new BeanSearchSpec(context, metadata,
					ConditionalOnMissingBean.class);
			// 查找结果
			MatchResult matchResult = getMatchingBeans(context, spec);
			// 只要有任意条件匹配上（注解、bean 名和 类型三者中匹配上一个）则返回失败的消息
			if (matchResult.isAnyMatched()) {
				String reason = createOnMissingBeanNoMatchReason(matchResult);
				return ConditionOutcome.noMatch(ConditionMessage
						.forCondition(ConditionalOnMissingBean.class, spec)
						.because(reason));
			}
			// 都没有匹配上返回成功的消息
			matchMessage = matchMessage.andCondition(ConditionalOnMissingBean.class, spec)
					.didNotFind("any beans").atAll();
		}
		// 返回最终的匹配结果
		return ConditionOutcome.match(matchMessage);
	}

	// 匹配逻辑：先通过bean类型查找，然后是通过注解方式查找最后是通过beanName查找，匹配结果放在 matchResult 里。
	protected final MatchResult getMatchingBeans(ConditionContext context,
												 BeanSearchSpec beans) {
		ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
		// 匹配策略是只到父容器查询则把父容器强转成 ConfigurableListableBeanFactory
		if (beans.getStrategy() == SearchStrategy.ANCESTORS) {
			BeanFactory parent = beanFactory.getParentBeanFactory();
			Assert.isInstanceOf(ConfigurableListableBeanFactory.class, parent,
					"Unable to use SearchStrategy.PARENTS");
			beanFactory = (ConfigurableListableBeanFactory) parent;
		}
		// 创建匹配结果的对象
		MatchResult matchResult = new MatchResult();
		// true表示不到当前的容器查询，false表示只在当前容器查找。
		boolean considerHierarchy = beans.getStrategy() != SearchStrategy.CURRENT;
		// 获取查找对象的类型
		TypeExtractor typeExtractor = beans.getTypeExtractor(context.getClassLoader());
		// 通过bean类型获取要忽略的bean
		List<String> beansIgnoredByType = getNamesOfBeansIgnoredByType(
				beans.getIgnoredTypes(), typeExtractor, beanFactory, context,
				considerHierarchy);
		// 通过bean类型匹配
		// 遍历要查找的bean类型
		for (String type : beans.getTypes()) {
			// 通过类型查询出beanName
			Collection<String> typeMatches = getBeanNamesForType(beanFactory, type,
					typeExtractor, context.getClassLoader(), considerHierarchy);
			// 过滤掉忽略的bean类型
			typeMatches.removeAll(beansIgnoredByType);
			// 为空说明没有找到，则把当前bean类型记录下来，表示没有匹配成功。
			if (typeMatches.isEmpty()) {
				matchResult.recordUnmatchedType(type);
			} else {
				// 匹配成功
				matchResult.recordMatchedType(type, typeMatches);
			}
		}
		// 遍通过注解匹配
		for (String annotation : beans.getAnnotations()) {
			// bean 注解list
			List<String> annotationMatches = Arrays
					.asList(getBeanNamesForAnnotation(beanFactory, annotation,
							context.getClassLoader(), considerHierarchy));
			// 过滤掉忽略的bean类型
			annotationMatches.removeAll(beansIgnoredByType);
			// 记录下没有匹配成功的注解
			if (annotationMatches.isEmpty()) {
				matchResult.recordUnmatchedAnnotation(annotation);
			} else {
				// 记录下匹配成功的注解
				matchResult.recordMatchedAnnotation(annotation, annotationMatches);
			}
		}
		// 要查找的bean不在忽略的范围内并且在容器里存在则把当前bean标记为匹配成功。
		for (String beanName : beans.getNames()) {
			if (!beansIgnoredByType.contains(beanName)
					&& containsBean(beanFactory, beanName, considerHierarchy)) {
				matchResult.recordMatchedName(beanName);
			} else {
				matchResult.recordUnmatchedName(beanName);
			}
		}
		return matchResult;
	}

	private String[] getBeanNamesForAnnotation(
			ConfigurableListableBeanFactory beanFactory, String type,
			ClassLoader classLoader, boolean considerHierarchy) throws LinkageError {
		Set<String> names = new HashSet<>();
		try {
			@SuppressWarnings("unchecked")
			Class<? extends Annotation> annotationType = (Class<? extends Annotation>) ClassUtils
					.forName(type, classLoader);
			collectBeanNamesForAnnotation(names, beanFactory, annotationType,
					considerHierarchy);
		} catch (ClassNotFoundException ex) {
			// Continue
		}
		return StringUtils.toStringArray(names);
	}

	private void collectBeanNamesForAnnotation(Set<String> names,
											   ListableBeanFactory beanFactory, Class<? extends Annotation> annotationType,
											   boolean considerHierarchy) {
		BeanTypeRegistry registry = BeanTypeRegistry.get(beanFactory);
		names.addAll(registry.getNamesForAnnotation(annotationType));
		if (considerHierarchy) {
			BeanFactory parent = ((HierarchicalBeanFactory) beanFactory)
					.getParentBeanFactory();
			if (parent instanceof ListableBeanFactory) {
				collectBeanNamesForAnnotation(names, (ListableBeanFactory) parent,
						annotationType, considerHierarchy);
			}
		}
	}

	private List<String> getNamesOfBeansIgnoredByType(List<String> ignoredTypes,
													  TypeExtractor typeExtractor, ListableBeanFactory beanFactory,
													  ConditionContext context, boolean considerHierarchy) {
		List<String> beanNames = new ArrayList<>();
		for (String ignoredType : ignoredTypes) {
			beanNames.addAll(getBeanNamesForType(beanFactory, ignoredType, typeExtractor,
					context.getClassLoader(), considerHierarchy));
		}
		return beanNames;
	}

	// considerHierarchy 为true,表示bean是不是要在父子容器查找，false表示只在当前容器查找
	private boolean containsBean(ConfigurableListableBeanFactory beanFactory,
								 String beanName, boolean considerHierarchy) {
		if (considerHierarchy) {
			return beanFactory.containsBean(beanName);
		}
		return beanFactory.containsLocalBean(beanName);
	}

	private Collection<String> getBeanNamesForType(ListableBeanFactory beanFactory,
												   String type, TypeExtractor typeExtractor, ClassLoader classLoader,
												   boolean considerHierarchy) throws LinkageError {
		try {
			return getBeanNamesForType(beanFactory, considerHierarchy,
					ClassUtils.forName(type, classLoader), typeExtractor);
		} catch (ClassNotFoundException | NoClassDefFoundError ex) {
			return Collections.emptySet();
		}
	}

	private Collection<String> getBeanNamesForType(ListableBeanFactory beanFactory,
												   boolean considerHierarchy, Class<?> type, TypeExtractor typeExtractor) {
		Set<String> result = new LinkedHashSet<>();
		collectBeanNamesForType(result, beanFactory, type, typeExtractor,
				considerHierarchy);
		return result;
	}

	private void collectBeanNamesForType(Set<String> result,
										 ListableBeanFactory beanFactory, Class<?> type, TypeExtractor typeExtractor,
										 boolean considerHierarchy) {
		BeanTypeRegistry registry = BeanTypeRegistry.get(beanFactory);
		result.addAll(registry.getNamesForType(type, typeExtractor));
		if (considerHierarchy && beanFactory instanceof HierarchicalBeanFactory) {
			BeanFactory parent = ((HierarchicalBeanFactory) beanFactory)
					.getParentBeanFactory();
			if (parent instanceof ListableBeanFactory) {
				collectBeanNamesForType(result, (ListableBeanFactory) parent, type,
						typeExtractor, considerHierarchy);
			}
		}
	}

	private String createOnBeanNoMatchReason(MatchResult matchResult) {
		StringBuilder reason = new StringBuilder();
		appendMessageForNoMatches(reason, matchResult.getUnmatchedAnnotations(),
				"annotated with");
		appendMessageForNoMatches(reason, matchResult.getUnmatchedTypes(), "of type");
		appendMessageForNoMatches(reason, matchResult.getUnmatchedNames(), "named");
		return reason.toString();
	}

	private void appendMessageForNoMatches(StringBuilder reason,
										   Collection<String> unmatched, String description) {
		if (!unmatched.isEmpty()) {
			if (reason.length() > 0) {
				reason.append(" and ");
			}
			reason.append("did not find any beans ");
			reason.append(description);
			reason.append(" ");
			reason.append(StringUtils.collectionToDelimitedString(unmatched, ", "));
		}
	}

	private String createOnMissingBeanNoMatchReason(MatchResult matchResult) {
		StringBuilder reason = new StringBuilder();
		appendMessageForMatches(reason, matchResult.getMatchedAnnotations(),
				"annotated with");
		appendMessageForMatches(reason, matchResult.getMatchedTypes(), "of type");
		if (!matchResult.getMatchedNames().isEmpty()) {
			if (reason.length() > 0) {
				reason.append(" and ");
			}
			reason.append("found beans named ");
			reason.append(StringUtils
					.collectionToDelimitedString(matchResult.getMatchedNames(), ", "));
		}
		return reason.toString();
	}

	private void appendMessageForMatches(StringBuilder reason,
										 Map<String, Collection<String>> matches, String description) {
		if (!matches.isEmpty()) {
			matches.forEach((key, value) -> {
				if (reason.length() > 0) {
					reason.append(" and ");
				}
				reason.append("found beans ");
				reason.append(description);
				reason.append(" '");
				reason.append(key);
				reason.append("' ");
				reason.append(StringUtils.collectionToDelimitedString(value, ", "));
			});
		}
	}

	private boolean hasSingleAutowireCandidate(
			ConfigurableListableBeanFactory beanFactory, Set<String> beanNames,
			boolean considerHierarchy) {
		return (beanNames.size() == 1
				|| getPrimaryBeans(beanFactory, beanNames, considerHierarchy)
				.size() == 1);
	}

	private List<String> getPrimaryBeans(ConfigurableListableBeanFactory beanFactory,
										 Set<String> beanNames, boolean considerHierarchy) {
		List<String> primaryBeans = new ArrayList<>();
		for (String beanName : beanNames) {
			BeanDefinition beanDefinition = findBeanDefinition(beanFactory, beanName,
					considerHierarchy);
			if (beanDefinition != null && beanDefinition.isPrimary()) {
				primaryBeans.add(beanName);
			}
		}
		return primaryBeans;
	}

	private BeanDefinition findBeanDefinition(ConfigurableListableBeanFactory beanFactory,
											  String beanName, boolean considerHierarchy) {
		if (beanFactory.containsBeanDefinition(beanName)) {
			return beanFactory.getBeanDefinition(beanName);
		}
		if (considerHierarchy && beanFactory
				.getParentBeanFactory() instanceof ConfigurableListableBeanFactory) {
			return findBeanDefinition(((ConfigurableListableBeanFactory) beanFactory
					.getParentBeanFactory()), beanName, considerHierarchy);
		}
		return null;
	}
	// 封装查询bean的条件
	protected static class BeanSearchSpec {
		// 注解类型
		private final Class<?> annotationType;
		// beanName
		private final List<String> names = new ArrayList<>();
		// beanType
		private final List<String> types = new ArrayList<>();
		// 注解
		private final List<String> annotations = new ArrayList<>();
		// 忽略的beanType
		private final List<String> ignoredTypes = new ArrayList<>();
		// 存储参数的容器
		private final List<String> parameterizedContainers = new ArrayList<>();
		// 查询策略
		private final SearchStrategy strategy;

		public BeanSearchSpec(ConditionContext context, AnnotatedTypeMetadata metadata,
							  Class<?> annotationType) {
			this(context, metadata, annotationType, null);
		}

		public BeanSearchSpec(ConditionContext context, AnnotatedTypeMetadata metadata,
							  Class<?> annotationType, Class<?> genericContainer) {
			this.annotationType = annotationType;
			MultiValueMap<String, Object> attributes = metadata
					.getAllAnnotationAttributes(annotationType.getName(), true);
			collect(attributes, "name", this.names);
			collect(attributes, "value", this.types);
			collect(attributes, "type", this.types);
			collect(attributes, "annotation", this.annotations);
			collect(attributes, "ignored", this.ignoredTypes);
			collect(attributes, "ignoredType", this.ignoredTypes);
			collect(attributes, "parameterizedContainer", this.parameterizedContainers);
			this.strategy = (SearchStrategy) attributes.getFirst("search");
			BeanTypeDeductionException deductionException = null;
			try {
				if (this.types.isEmpty() && this.names.isEmpty()) {
					addDeducedBeanType(context, metadata, this.types);
				}
			} catch (BeanTypeDeductionException ex) {
				deductionException = ex;
			}
			validate(deductionException);
		}

		protected void validate(BeanTypeDeductionException ex) {
			if (!hasAtLeastOne(this.types, this.names, this.annotations)) {
				String message = getAnnotationName()
						+ " did not specify a bean using type, name or annotation";
				if (ex == null) {
					throw new IllegalStateException(message);
				}
				throw new IllegalStateException(message + " and the attempt to deduce"
						+ " the bean's type failed", ex);
			}
		}

		private boolean hasAtLeastOne(List<?>... lists) {
			return Arrays.stream(lists).anyMatch((list) -> !list.isEmpty());
		}

		protected final String getAnnotationName() {
			return "@" + ClassUtils.getShortName(this.annotationType);
		}

		protected void collect(MultiValueMap<String, Object> attributes, String key,
							   List<String> destination) {
			List<?> values = attributes.get(key);
			if (values != null) {
				for (Object value : values) {
					if (value instanceof String[]) {
						Collections.addAll(destination, (String[]) value);
					} else {
						destination.add((String) value);
					}
				}
			}
		}

		private void addDeducedBeanType(ConditionContext context,
										AnnotatedTypeMetadata metadata, final List<String> beanTypes) {
			if (metadata instanceof MethodMetadata
					&& metadata.isAnnotated(Bean.class.getName())) {
				addDeducedBeanTypeForBeanMethod(context, (MethodMetadata) metadata,
						beanTypes);
			}
		}

		private void addDeducedBeanTypeForBeanMethod(ConditionContext context,
													 MethodMetadata metadata, final List<String> beanTypes) {
			try {
				Class<?> returnType = getReturnType(context, metadata);
				beanTypes.add(returnType.getName());
			} catch (Throwable ex) {
				throw new BeanTypeDeductionException(metadata.getDeclaringClassName(),
						metadata.getMethodName(), ex);
			}
		}

		private Class<?> getReturnType(ConditionContext context, MethodMetadata metadata)
				throws ClassNotFoundException, LinkageError {
			// We should be safe to load at this point since we are in the
			// REGISTER_BEAN phase
			ClassLoader classLoader = context.getClassLoader();
			Class<?> returnType = ClassUtils.forName(metadata.getReturnTypeName(),
					classLoader);
			if (isParameterizedContainer(returnType, classLoader)) {
				returnType = getReturnTypeGeneric(metadata, classLoader);
			}
			return returnType;
		}

		private Class<?> getReturnTypeGeneric(MethodMetadata metadata,
											  ClassLoader classLoader) throws ClassNotFoundException, LinkageError {
			Class<?> declaringClass = ClassUtils.forName(metadata.getDeclaringClassName(),
					classLoader);
			Method beanMethod = findBeanMethod(declaringClass, metadata.getMethodName());
			return ResolvableType.forMethodReturnType(beanMethod).resolveGeneric();
		}

		private Method findBeanMethod(Class<?> declaringClass, String methodName) {
			Method method = ReflectionUtils.findMethod(declaringClass, methodName);
			if (isBeanMethod(method)) {
				return method;
			}
			return Arrays.stream(ReflectionUtils.getAllDeclaredMethods(declaringClass))
					.filter((candidate) -> candidate.getName().equals(methodName))
					.filter(this::isBeanMethod).findFirst()
					.orElseThrow(() -> new IllegalStateException(
							"Unable to find bean method " + methodName));
		}

		private boolean isBeanMethod(Method method) {
			return method != null
					&& AnnotatedElementUtils.hasAnnotation(method, Bean.class);
		}

		public TypeExtractor getTypeExtractor(ClassLoader classLoader) {
			if (this.parameterizedContainers.isEmpty()) {
				return ResolvableType::resolve;
			}
			return (type) -> {
				Class<?> resolved = type.resolve();
				if (isParameterizedContainer(resolved, classLoader)) {
					return type.getGeneric().resolve();
				}
				return resolved;
			};
		}

		private boolean isParameterizedContainer(Class<?> type, ClassLoader classLoader) {
			for (String candidate : this.parameterizedContainers) {
				try {
					if (ClassUtils.forName(candidate, classLoader)
							.isAssignableFrom(type)) {
						return true;
					}
				} catch (Exception ex) {
				}
			}
			return false;
		}

		public SearchStrategy getStrategy() {
			return (this.strategy != null) ? this.strategy : SearchStrategy.ALL;
		}

		public List<String> getNames() {
			return this.names;
		}

		public List<String> getTypes() {
			return this.types;
		}

		public List<String> getAnnotations() {
			return this.annotations;
		}

		public List<String> getIgnoredTypes() {
			return this.ignoredTypes;
		}

		@Override
		public String toString() {
			StringBuilder string = new StringBuilder();
			string.append("(");
			if (!this.names.isEmpty()) {
				string.append("names: ");
				string.append(StringUtils.collectionToCommaDelimitedString(this.names));
				if (!this.types.isEmpty()) {
					string.append("; ");
				}
			}
			if (!this.types.isEmpty()) {
				string.append("types: ");
				string.append(StringUtils.collectionToCommaDelimitedString(this.types));
			}
			string.append("; SearchStrategy: ");
			string.append(this.strategy.toString().toLowerCase(Locale.ENGLISH));
			string.append(")");
			return string.toString();
		}

	}

	private static class SingleCandidateBeanSearchSpec extends BeanSearchSpec {

		SingleCandidateBeanSearchSpec(ConditionContext context,
									  AnnotatedTypeMetadata metadata, Class<?> annotationType) {
			super(context, metadata, annotationType);
		}

		@Override
		protected void collect(MultiValueMap<String, Object> attributes, String key,
							   List<String> destination) {
			super.collect(attributes, key, destination);
			destination.removeAll(Arrays.asList("", Object.class.getName()));
		}

		@Override
		protected void validate(BeanTypeDeductionException ex) {
			Assert.isTrue(getTypes().size() == 1, () -> getAnnotationName()
					+ " annotations must specify only one type (got " + getTypes() + ")");
		}

	}

	protected static final class MatchResult {

		private final Map<String, Collection<String>> matchedAnnotations = new HashMap<>();

		private final List<String> matchedNames = new ArrayList<>();

		private final Map<String, Collection<String>> matchedTypes = new HashMap<>();

		private final List<String> unmatchedAnnotations = new ArrayList<>();

		private final List<String> unmatchedNames = new ArrayList<>();

		private final List<String> unmatchedTypes = new ArrayList<>();

		private final Set<String> namesOfAllMatches = new HashSet<>();

		private void recordMatchedName(String name) {
			this.matchedNames.add(name);
			this.namesOfAllMatches.add(name);
		}

		private void recordUnmatchedName(String name) {
			this.unmatchedNames.add(name);
		}

		private void recordMatchedAnnotation(String annotation,
											 Collection<String> matchingNames) {
			this.matchedAnnotations.put(annotation, matchingNames);
			this.namesOfAllMatches.addAll(matchingNames);
		}

		private void recordUnmatchedAnnotation(String annotation) {
			this.unmatchedAnnotations.add(annotation);
		}

		private void recordMatchedType(String type, Collection<String> matchingNames) {
			this.matchedTypes.put(type, matchingNames);
			this.namesOfAllMatches.addAll(matchingNames);
		}

		private void recordUnmatchedType(String type) {
			this.unmatchedTypes.add(type);
		}

		public boolean isAllMatched() {
			return this.unmatchedAnnotations.isEmpty() && this.unmatchedNames.isEmpty()
					&& this.unmatchedTypes.isEmpty();
		}

		public boolean isAnyMatched() {
			return (!this.matchedAnnotations.isEmpty()) || (!this.matchedNames.isEmpty())
					|| (!this.matchedTypes.isEmpty());
		}

		public Map<String, Collection<String>> getMatchedAnnotations() {
			return this.matchedAnnotations;
		}

		public List<String> getMatchedNames() {
			return this.matchedNames;
		}

		public Map<String, Collection<String>> getMatchedTypes() {
			return this.matchedTypes;
		}

		public List<String> getUnmatchedAnnotations() {
			return this.unmatchedAnnotations;
		}

		public List<String> getUnmatchedNames() {
			return this.unmatchedNames;
		}

		public List<String> getUnmatchedTypes() {
			return this.unmatchedTypes;
		}

		public Set<String> getNamesOfAllMatches() {
			return this.namesOfAllMatches;
		}

	}

	static final class BeanTypeDeductionException extends RuntimeException {

		private BeanTypeDeductionException(String className, String beanMethodName,
										   Throwable cause) {
			super("Failed to deduce bean type for " + className + "." + beanMethodName,
					cause);
		}

	}

}
