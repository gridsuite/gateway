package org.gridsuite.gateway;

import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.assertj.core.api.WithAssertions;
import org.gridsuite.gateway.endpoints.*;
import org.gridsuite.gateway.filters.ElementAccessControllerGlobalPreFilter;
import org.gridsuite.gateway.filters.TokenValidatorGlobalPreFilter;
import org.gridsuite.gateway.filters.UserAdminControlGlobalPreFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.WebsocketRoutingFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import reactor.test.StepVerifier;

import java.util.Map;

@Slf4j
@SpringBootTest
class GatewayApplicationTest implements WithAssertions {
    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private RouteLocator myRoutes;

    @Test
    void testAllEndpointServersFound() {
        assertThat(applicationContext.getBeansOfType(EndPointServer.class)).as("found EndPointServer beans")
            .allSatisfy((name, srv) -> assertThat(name).isEqualTo(srv.getEndpointName()))
            .extracting(Map::values, InstanceOfAssertFactories.collection(EndPointServer.class)).as("EndPointServer beans")
            .doesNotHaveDuplicates()
            .extracting(EndPointServer::getClass).as("EndPointServer classes")
            .containsExactlyInAnyOrder(
                CaseImportServer.class,
                CaseServer.class,
                CgmesBoundaryServer.class,
                CgmesGlServer.class,
                ConfigNotificationServer.class,
                ConfigServer.class,
                ContingencyServer.class,
                DirectoryNotificationServer.class,
                DirectoryServer.class,
                DynamicMappingServer.class,
                DynamicSimulationServer.class,
                ExploreServer.class,
                FilterServer.class,
                GeoDataServer.class,
                LoadFlowServer.class,
                MergeNotificationServer.class,
                MergeServer.class,
                NetworkConversionServer.class,
                NetworkModificationServer.class,
                OdreServer.class,
                ReportServer.class,
                SecurityAnalysisServer.class,
                SensitivityAnalysisServer.class,
                ShortCircuitServer.class,
                StudyNotificationServer.class,
                StudyServer.class,
                UserAdminServer.class,
                VoltageInitServer.class
        );
    }

    @Test
    void testRoutesInitialized() {
        StepVerifier.create(myRoutes.getRoutes())
                    .as("routes found")
                    .expectNextCount(28)
                    .verifyComplete();
    }

    @Test
    void testFiltersOrder() {
        assertThat(applicationContext.getBeansOfType(GlobalFilter.class)
                                     .values()
                                     .stream()
                                     .sorted(AnnotationAwareOrderComparator.INSTANCE) //sort work only on bean instances
                                     .peek(f -> log.info("p={} ; o={} ; {}", AAOC.INSTANCE.getPriority(f), AAOC.INSTANCE.getOrder(f), f.getClass().getName()))
                                     .map(GlobalFilter::getClass)
                                     .toList()).as("global filters found")
            // Before ElementAccessControllerGlobalPreFilter to enforce authentication
            .containsSubsequence(TokenValidatorGlobalPreFilter.class, ElementAccessControllerGlobalPreFilter.class)
            // Before WebsocketRoutingFilter to control access
            .containsSubsequence(ElementAccessControllerGlobalPreFilter.class, WebsocketRoutingFilter.class)
            .containsSubsequence(
                TokenValidatorGlobalPreFilter.class, //Ordered.LOWEST_PRECEDENCE - 4
                UserAdminControlGlobalPreFilter.class, //Ordered.LOWEST_PRECEDENCE - 3
                ElementAccessControllerGlobalPreFilter.class //Ordered.LOWEST_PRECEDENCE - 2
        );
    }

    private static class AAOC extends AnnotationAwareOrderComparator {
        public static final AAOC INSTANCE = new AAOC();

        @Override
        public int getOrder(final Object obj) {
            return super.getOrder(obj);
        }
    }
}
