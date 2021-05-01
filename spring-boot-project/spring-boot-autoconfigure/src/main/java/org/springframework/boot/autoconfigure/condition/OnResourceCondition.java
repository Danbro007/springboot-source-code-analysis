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

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionMessage.Style;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;

/**
 * {@link Condition} that checks for specific resources.
 *
 * @author Dave Syer
 * @see ConditionalOnResource
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
class OnResourceCondition extends SpringBootCondition {

	private final ResourceLoader defaultResourceLoader = new DefaultResourceLoader();

	// 获取ConditionalOnResource注解上的资源路径，遍历它们
	// 找不到的资源路径到 missing 这个list里，遍历完毕判断 missing 是否为空，
	// 如果不为空则返回一个匹配失败的ConditionOutcome，把没有找到的资源路径放到这个ConditionOutcome里
	// 如果为空则返回一个匹配成功的 ConditionOutcome
	@Override
	public ConditionOutcome getMatchOutcome(ConditionContext context,
			AnnotatedTypeMetadata metadata) {
		// 获取@ConditionalOnResource注解上的资源路径
		MultiValueMap<String, Object> attributes = metadata
				.getAllAnnotationAttributes(ConditionalOnResource.class.getName(), true);
		// 获取资源加载器
		ResourceLoader loader = (context.getResourceLoader() != null)
				? context.getResourceLoader() : this.defaultResourceLoader;
		List<String> locations = new ArrayList<>();
		// 把资源路径放到 locations 里
		collectValues(locations, attributes.get("resources"));
		Assert.isTrue(!locations.isEmpty(),
				"@ConditionalOnResource annotations must specify at "
						+ "least one resource location");
		List<String> missing = new ArrayList<>();
		// 遍历每个资源路径并加载它们，如果加载失败即资源不存在则把不存在的资源路径放到 missing 里
		for (String location : locations) {
			String resource = context.getEnvironment().resolvePlaceholders(location);
			if (!loader.getResource(resource).exists()) {
				missing.add(location);
			}
		}
		// 创建一个 ConditionOutcome 实例包括没有匹配成功的资源信息
		if (!missing.isEmpty()) {
			return ConditionOutcome.noMatch(ConditionMessage
					.forCondition(ConditionalOnResource.class)
					.didNotFind("resource", "resources").items(Style.QUOTE, missing));
		}
		// 创建一个 ConditionOutcome 实例包括匹配的资源信息
		return ConditionOutcome
				.match(ConditionMessage.forCondition(ConditionalOnResource.class)
						.found("location", "locations").items(locations));
	}

	private void collectValues(List<String> names, List<Object> values) {
		for (Object value : values) {
			for (Object item : (Object[]) value) {
				names.add((String) item);
			}
		}
	}

}
